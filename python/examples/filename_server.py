import glob
from SimpleXMLRPCServer import SimpleXMLRPCServer
import sys

fileNameList = []
idx = 0


def nextFileName():
    global idx
    if idx >= len(fileNameList):
        return None
    out = fileNameList[idx]
    idx += 1
    print "{}/{}: {}".format(idx, len(fileNameList), out)
    return out


total_ref = 0
total_fp = 0
total_fn = 0
total_found = 0
results = 0
len_possible_missed = 0


def reportResult(filename,
                 reference_functions,  # count
                 pre_sweep_functions,  # count
                 post_sweep_functions,  # count
                 false_negatives,  # list
                 false_positives,  # list
                 possible_missed,  # list of lists
                 seconds):
    global total_ref
    global total_fp
    global total_fn
    global total_found
    global results
    global len_possible_missed
    total_ref += reference_functions
    total_fp += len(false_positives)
    total_fn += len(false_negatives)
    total_found += post_sweep_functions - pre_sweep_functions
    results += 1
    len_possible_missed += len(possible_missed)
    # Now we have all the information needed for our record
    print "{seconds}s File: {0} TotalRefFunctions: {1} PostSweep: {2} SweepFound: {3} FalsePositives: {4} %{5:.2f} FalseNegatives: {6} %{7:.2f} FNs {fns}, FPs {fps} PossibleMissed {missed}".format(
        filename,
        reference_functions,
        post_sweep_functions,
        post_sweep_functions - pre_sweep_functions,
        len(false_positives), 100 * (len(false_positives) / float(reference_functions)),
        len(false_negatives), 100 * (len(false_negatives) / float(reference_functions)),
        fns=str(map(hex, false_negatives)), fps=str(map(hex, false_positives)),
        seconds=seconds,
        missed=possible_missed)

    if results == len(fileNameList):
        print_results()
        sys.exit()


def main():
    global fileNameList
    global idx
    if len(sys.argv) < 2:
        print "usage: {} <filenames_glob> [ startIdx ]".format(sys.argv[0])
        return

    fileNameList = glob.glob(sys.argv[1])
    fileNameList = filter(lambda x: not x.endswith('_stripped.bndb'), fileNameList)
    if len(sys.argv) > 2:
        idx = int(sys.argv[2])
    server = SimpleXMLRPCServer(("0.0.0.0", 8000), allow_none=True, logRequests=False)
    server.register_function(nextFileName, "nextFileName")
    server.register_function(reportResult, "reportResult")
    server.serve_forever()


def print_results():
    print ("Overall Total Functions: {total_ref}\n"
           "Overall Functions found: {total_found} %{pfnd:.2f}\n"
           "Overall False Positives: {total_fp} %{pfp:.2f}\n"
           "Overall False Negatives: {total_fn} %{pfn:.2f}\n"
           "Overall Possible missed: {missed}\n").format(
           total_ref=total_ref,
           total_found=total_found, pfnd=(100 * total_found / float(total_ref)),
           total_fp=total_fp, pfp=(100 * total_fp / float(total_ref)),
           total_fn=total_fn, pfn=(100 * total_fn / float(total_ref)),
           missed=len_possible_missed)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_results()
