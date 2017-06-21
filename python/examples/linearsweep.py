import binaryninja
from binaryninja.enums import LowLevelILOperation, BranchType
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.log import log_info, log_error
from binaryninja.lowlevelil import ILRegister

instruction_alignment = {'x86': 1, 'x86_64': 1, 'thumb2': 2, 'armv7': 4, 'aarch64': 4, 'mips32': 4}
required_function_alignment = {'x86': 1, 'x86_64': 1, 'thumb2': 2, 'armv7': 4, 'aarch64': 4, 'mips32': 4}
preferred_function_alignement = {'x86': 16, 'x86_64': 16, 'thumb2': 2, 'armv7': 4, 'aarch64': 4, 'mips32': 4}


def is_il_set_reg_reg(il):
	return (il.operation == LowLevelILOperation.LLIL_SET_REG and
		   isinstance(il.operands[0], ILRegister) and
		   il.operands[1].operation == LowLevelILOperation.LLIL_REG and
		   il.operands[0] == il.operands[1].operands[0])


def get_next_unknown_data_after(bv, addr):
	var = bv.get_data_var_at(addr)
	blocks = bv.get_basic_blocks_at(addr)
	if len(blocks) == 0 and (var is None):
		return addr
	if len(blocks) == 0 and (var is not None) and var.type.width == 0:
		return addr

	ea = bv.get_next_data_after(addr)
	var = bv.get_data_var_at(ea)
	while var is not None:
		if var.type.width == 0:
			break
		ea = bv.get_next_data_after(ea + var.type.width - 1)
		var = bv.get_data_var_at(ea)
	return ea


def is_call_instruction(bv, addr):
	info = bv.arch.get_instruction_info(bv.read(addr, bv.arch._get_max_instruction_length(None)), addr)
	if info is None:
		return (1, [])
	calls = []
	for branch in info.branches:
		if branch.type == BranchType.CallDestination:
			calls.append(branch)
	return (info.length, calls)


def is_function_well_formed(bv, func):
	for bb in func.low_level_il.basic_blocks:
		if len(bb.outgoing_edges) == 0:
			if bb[-1].operation not in (LowLevelILOperation.LLIL_RET, LowLevelILOperation.LLIL_NORET):
				if bb[-1].operation == LowLevelILOperation.LLIL_JUMP:
						if bb[-1].operands[0].operation == LowLevelILOperation.LLIL_CONST:
							# We have a jump out
							continue
						if bb.has_undetermined_outgoing_edges:
							# We have a undetermined jump table
							continue
						if bb[-1].dest.operation != LowLevelILOperation.LLIL_CONST:
							continue
						elif bv.get_basic_blocks_at(bb[-1].dest.value) is not None:
							# Tail call
							continue
				return False
	return True


# TODO: need per bv list of sections which are code sections
codeSects = ['.text', '.init', '.fini', '.plt', '__text', '__symbol_stub', '__symbol_stub', 'PAGE', 'PAGE8FIL', 'INIT']


def in_code_section(bv, addr):
	addrSects = bv.get_sections_at(addr)
	status = False
	for sect in addrSects:
		if sect.name in codeSects:
			status = True
			break
	return status


def find_calls_in_code_sections(bv):
	# General algorithm
	# 1. Scan "code sections" as defined by the BinaryView for call instruction
	# 2. Given a call target, ensure it points into a clode section and that address is executable
	# 3. Save off that address
	# 4. Sort all the call targets in order of most frequently referenced
	# 5. Go through the list of call targets and create functions one at a time, if
	#    a. The target is not in a basic block
	#    b. The target is not in a data variable
	#    c. The target is in a code section
	#    d. The target is in an executable segment
	# 6. Once the Function has been added we can do additional checks for if the Function is "well formed"
	#    a. All basic blocks must end in a LLIL_RET, LLIL_NO_RET, or a JUMP
	#    b. Jumps can be of three forms
	#       i.   Jump to a constant address (standard jump or jumpout)
	#       ii.  Jump table
	#       iii. ...
	# TODO: Proposed speed improvement: Multi-thread it
	#         a. Divide up the code sections into contiguous blocks of unknown data.
	#            (i.e. Start and end address that have no basic blocks or data variables in them)
	#         b. Create a thread pool to handle this list.

	starts = {}  # map of starts[call.target] = [call.address1, call.address2, ...]
	secs = filter(lambda sec: sec[1].name in codeSects, bv.sections.items())
	for name, sec in secs:
		# Skip anything defined as a basic block or data of known size
		ea = get_next_unknown_data_after(bv, sec.start)
		while ea < sec.end:
			(size, calls) = is_call_instruction(bv, ea)
			if size == 0:
				log_info("get_instruction_info returned 0")
				return
			if bv.is_offset_executable(ea):
				for call in calls:
					if bv.get_function_at(call.target) is None:
						if call.target not in starts:
							starts[call.target] = [ea]
						else:
							starts[call.target].append(ea)

			prev_ea = ea
			ea = get_next_unknown_data_after(bv, ea + size)
			if ea <= prev_ea:  # Make sure we don't inf loop
				log_info("Failed to get next ea at: {0:x}".format(prev_ea))
				break

	# Sort by count since higher count probably means more likely to be a function start
	created = []
	starts = sorted(starts.items(), key=lambda x: len(x[1]), reverse=True)
	for addr, sources in starts:
		if not bv.is_offset_executable(addr):  # offset must be executable
			continue
		if not in_code_section(bv, addr):  # offset must be in "code" section
			continue
		if len(bv.get_basic_blocks_at(addr)) > 0:  # offset must not have existing basic blocks
			continue

		bv.add_function(addr)
		bv.update_analysis_and_wait()
		func = bv.get_function_at(addr)
		if not is_function_well_formed(bv, func):  # Remove the function if its not well formed
			bv.remove_user_function(func)
			bv.update_analysis_and_wait()
		else:
			created.append(addr)
	return created


# List of all discovered basic blocks
class BasicBlockList(object):
	def __init__(self):
		self.blocks = {}

	def address_is_block_start(self, address):
		return address in self.blocks

	def get_containing_block(self, address):
		for curStart in self.blocks.keys():
			if (address > curStart) and (address < curStart + self.blocks[curStart].length):
				return self.blocks[curStart]
		return None

	def address_in_existing_block(self, address):
		return (self.get_containing_block(address) is not None)

	def add_block(self, block):
		if self.address_is_block_start(block.start) or self.address_in_existing_block(block.start):
			raise Exception("Attempting to add same basic block twice")
		# I think we can get away with out checking for different types of overlap
		# Be aware we can add blocks that span multiple other basic blocks but we should never do that
		# We could check but its too expensive of a check.
		self.blocks[block.start] = block

	def get_block(self, start, autoSplitBlock=True):
		if self.address_is_block_start(start):
			return self.blocks[start]
		# Might be pointing within a basic block
		if autoSplitBlock:
			block = self.get_containing_block(start)
			if block is not None:
				new_block = BasicBlock(start, block.start + block.length - start)
				new_block.preds = [block.start]
				new_block.succs = block.succs
				block.succs = new_block.start
				self.blocks[start] = new_block
				block.length = block.length - (new_block.start - block.start)
				return new_block
		raise Exception("No basic block at this address")


class BasicBlock(object):
	def __init__(self, start, length, last_instruction_address, calls_no_return):
		self.start = start
		self.length = length
		self.succs = []  # indicies into basic_blocks
		self.preds = []  # indicies into basic_blocks
		self.last_instruction_address = last_instruction_address
		self.calls_no_return = calls_no_return
		self.parent = None

	def add_succs(self, succs):
		if isinstance(succs, list):
			self.succs.extend(succs)
		else:
			self.succs.append(succs)

	def add_preds(self, preds):
		if isinstance(preds, list):
			self.preds.extend(preds)
		else:
			self.preds.append(preds)


def find_basic_block_start(bv, start, length):
	ea = start
	while ea < start + length:
		il = bv.arch.get_instruction_low_level_il_instruction(bv, ea)
		ins_len = bv.get_instruction_length(ea)
		if il.operation in (LowLevelILOperation.LLIL_NOP, LowLevelILOperation.LLIL_BP, LowLevelILOperation.LLIL_TRAP):
			ea += ins_len
			continue

		if is_il_set_reg_reg(il):
			# We have a `reg = reg` commonly used for padding
			if (bv.platform.name in ("windows-x86", "windows-x86_64") and il.operands[0] == 'edi' and il.operands[1].operands[0] == 'edi'):
				# special case mov edi, edi used in Windows x86/x64
				return ea
			ea += ins_len
			continue
		break
	return ea


def get_instruction_info(bv, address):
	return bv.arch.get_instruction_info(bv.read(address, bv.arch._get_max_instruction_length(None)), address)


def calls_no_return(bv, branch):
	if branch.type == BranchType.CallDestination:
		target_func = bv.get_function_at(branch.target)
		if target_func is not None and not target_func.can_return:
			return True
	return False


def instruction_ends_basic_block(bv, address):
	info = get_instruction_info(bv, address)
	if info is None:
		return (True, info, False)
	if len(info.branches) == 0:
		return (False, info, False)
	if len(info.branches) == 1 and calls_no_return(bv, info.branches[0]):  # Unconditional call to no-return function
		return (True, info, True)

	for branch in info.branches:
		if branch.type in (BranchType.UnconditionalBranch,
			BranchType.FalseBranch,
			BranchType.TrueBranch,
			BranchType.FunctionReturn,
			BranchType.IndirectBranch,
			BranchType.UnresolvedBranch):
			return (True, info, False)
	return (False, info, False)


def assign_blocks_to(bv, basic_block_list, visited_blocks, cur_block, parent):
	block = basic_block_list.blocks[cur_block]
	to_visit = set(block.succs).union(set(block.preds))
	visited_blocks.add(cur_block)
	block_count = 1
	# Only visit each block once
	for visited_block in visited_blocks:
		if visited_block in to_visit:
			to_visit.remove(visited_block)

	for start in to_visit:
		# Check if a block already exists here
		existing_block = bv.get_basic_blocks_starting_at(start)
		if existing_block is not None:
			# TODO: What should we do here? We have a unidentified basic block
			# that connects to an identified basic block
			visited_blocks.add(start)
			continue

		# Check if this is a unidentified basic block
		if basic_block_list.address_is_block_start(start):
			basic_block_list[start].parent = parent
			block_count += assign_blocks_to(bv, basic_block_list, block, parent)
			continue

		# Target is pointing into the middle of a unidentified basic block
		if basic_block_list.address_in_existing_block(start):
			basic_block_list.add_block(start)
			basic_block_list[start].parent = parent
			block_count += assign_blocks_to(bv, basic_block_list, visited_blocks, block, parent)
			continue

		# Target is pointing into data?
		visited_blocks.add(start)
		log_error("Target pointing into data? Parent BB: %08x Target: %08x" % (block.start, start))
		# TODO: Maybe we need to remove this as a potential function
	return block_count


def orphan_function_scan(bv):
	# Algorithm for scanning for additional functions
	# 1. Create all basic blocks using most liberal definition possible no recursion.
	#    a. Including padding, start disassembling looking for a basic block end (JUMP, RET, NO_RET)
	#    b. Record that start and length.
	# 2. Go through the list of created basic blocks trying to connect them.
	#    a. If a basic block has a jump in the middle of it and not the top consider the top->middle as padding and discard
	# 3. Consider each set of connected basic blocks to be a quasi-function (qf)
	# 4. For each qf:
	#    a. Identify the entry point(s) - (node with 0 incoming edges)
	#    b. If the function has multiple entry points
	#       i. Choose the entry point with the lowest address
	#    c. If the qf has a single entry point
	#       i.   Look for common padding sequences at the begining of the function and increment the start.
    #       ii.  Create a real function and run analysis (hopefully this resolves any jump tables)
	#    d. if there are unresolved jump tables
	#       i.  Skip the next multi-entry qf
	#       ii. While next function has unresolved jump table goto i.
	basic_block_list = BasicBlockList()
	secs = filter(lambda sec: sec[1].name in codeSects, bv.sections.items())
	# print secs
	# Generate a list of regions that have no code and no data variables defined in them
	regions = []
	for sec_rec in secs:
		sec = sec_rec[1]
		unknown_region_start = get_next_unknown_data_after(bv, sec.start)
		while unknown_region_start < sec.end:
			unknown_region_end = min(bv.get_next_basic_block_start_after(unknown_region_start), sec.end)
			unknown_region_end = min(bv.get_next_data_var_after(unknown_region_start), unknown_region_end)
			regions.append((unknown_region_start, unknown_region_end))
			unknown_region_start = get_next_unknown_data_after(bv, unknown_region_end)

	# Go through all the unknown regions
	for start, end in regions:
		ea = start
		block_start = ea
		while ea < end:
			(doesEnd, info, is_no_return) = instruction_ends_basic_block(bv, ea)
			if info is None:  # Disassembling garbage
				ea += 1
				block_start = ea
				continue

			cur_end = ea + info.length
			if doesEnd:
				new_block = BasicBlock(block_start, cur_end - block_start, ea, is_no_return)
				if not is_no_return:
					for branch in info.branches:
						# Add all branches that aren't calls to no return functions
						if calls_no_return(bv, branch):
							continue
						new_block.add_succs(branch.target)

				basic_block_list.add_block(new_block)
				block_start = cur_end

			ea = cur_end

	# print map(lambda x: (hex(x[1].start), hex(x[1].length)), sorted(basic_block_list.blocks.items(), key=lambda x: x[1].start))
	# Add all pred blocks
	for start, block in basic_block_list.blocks.items():
		for succ in block.succs:
			if succ in basic_block_list.blocks:
				basic_block_list.blocks[succ].add_preds(start)

	# Now we can find all the blocks that have no preds, these are our function start blocks
	start_blocks = []
	for start, block in basic_block_list.blocks.items():
		if len(block.preds) == 0:
			start_blocks.append(block)

	potential_functions = {}
	# Now find groupings of basic blocks
	for block in start_blocks:
		if block.parent is None:
			block_count = assign_blocks_to(bv, basic_block_list, set(), block.start, block.start)
			potential_functions[block.start] = {"block": block, "block_count": block_count, "multi-entry": False}
		else:
			# We have a multi-entry function mark it as such
			info = potential_functions[block.parent]
			info["multi-entry"] = True
			potential_functions[block.parent] = info

	created = []
	# Now we go through the list of potential functions and ensure it doesn't start with common padding sequences
	for start in sorted(potential_functions.keys()):
		# Find the first non-nop instruction
		ea = find_basic_block_start(bv, start, basic_block_list.blocks[start].length)
		if ea == start + basic_block_list.blocks[start].length:
			continue

		if len(bv.get_basic_blocks_at(ea)) == 0:  # Ensure there isn't a function here already
			bv.add_function(ea)
			bv.update_analysis_and_wait()
			created.append(ea)

	return created


def tail_call_analysis(bv, orphan_created_functions):
	created = []
	# Try to find tail calls in the stuff we just created
	for func in orphan_created_functions:
		block_starts = sorted(map(lambda x: x.start, bv.get_function_at(func).basic_blocks))
		for start in block_starts:
			if len(bv.get_basic_blocks_at(start)) > 1 and bv.get_function_at(start) is None:
				# Multiple functions jump to this basic block, so lets make a function here instead
				bv.add_function(start)
				created.append(start)
				bv.update_analysis_and_wait()
				break
	return created


def linear_sweep(bv):
	# This step has a very low false positive rate, so we do it first
	created = find_calls_in_code_sections(bv)
	log_info("find_calls_in_code_sections created {} {} functions".format(len(created), map(hex, created)))
	created = orphan_function_scan(bv)
	log_info("orphan_function_scan created {} {} functions".format(len(created), map(hex, created)))
	created = tail_call_analysis(bv, created)
	log_info("tail_call_analysis created {} {} functions".format(len(created), map(hex, created)))


class LinearSweep(BackgroundTaskThread):
	def __init__(self, bv):
		BackgroundTaskThread.__init__(self, "Linear Sweeping", True)
		self.bv = bv

	def run(self):
		linear_sweep(self.bv)


def linear_sweep_thread(bv):
	ls = LinearSweep(bv)
	ls.start()


if __name__ != "__main__":
	binaryninja.PluginCommand.register("Linear Sweep", "Find additional functions using linear sweep", linear_sweep_thread)
