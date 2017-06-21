#!/usr/bin/env python
from binaryninja.binaryview import BinaryViewType
import linearsweep
import time
from optparse import OptionParser
import xmlrpclib


def do_ls(bv):
    ls = linearsweep.LinearSweep(bv)
    ls.run()


def remove_plt_functions(bv, function_starts):
    out = []
    for start in function_starts:
        if bv.get_sections_at(start)[0].name == '.plt':
            continue
        out.append(start)
    return out


def run_test(filename):
    bv = BinaryViewType.get_view_of_file(filename)
    if bv is None:
        print "Unable to open {0}".format(filename)
    reference_functions = map(lambda x: x.start, bv.functions)
    reference_functions = remove_plt_functions(bv, reference_functions)
    bv.file.close()

    print filename[:-5] + "_stripped.bndb"
    bv = BinaryViewType.get_view_of_file(filename[:-5] + "_stripped.bndb")
    if bv is None:
        print "Unable to open {0}".format(filename[:-5] + "_stripped.bndb")
    pre_sweep_functions = map(lambda x: x.start, bv.functions)
    pre_sweep_functions = remove_plt_functions(bv, pre_sweep_functions)
    # run linear Sweep
    start = time.time()
    do_ls(bv)
    seconds = int(time.time() - start)
    post_sweep_functions = map(lambda x: x.start, bv.functions)
    post_sweep_functions = remove_plt_functions(bv, post_sweep_functions)
    false_negatives = set(reference_functions) - set(post_sweep_functions)
    false_positives = set(post_sweep_functions) - set(reference_functions)

    possible_missed = []
    # for fn in false_negatives:
    #     preFunctions = bv.functions
    #     countBefore = len(preFunctions)
    #     bv.add_function(fn)
    #     bv.update_analysis_and_wait()
    #     if len(bv.functions) > countBefore + 1:
    #         possible_missed.append(fn)
    bv.file.close()
    return (len(reference_functions),
           len(pre_sweep_functions),
           len(post_sweep_functions),
           list(false_negatives),
           list(false_positives),
           possible_missed,
           seconds)


def main():
    total_ref = 0
    total_fp = 0
    total_fn = 0
    total_found = 0

    parser = OptionParser()
    parser.add_option("-d", "--distributed", dest="dist", action="store_true", default=False, help="Use distributed work queue")
    parser.add_option("-i", "--ip-port", dest="ip_port", metavar="IP:PORT", default="localhost:8000", help="Use specified server for distributed work queue")
    (options, args) = parser.parse_args()

    req = None
    if options.dist:
        req = xmlrpclib.ServerProxy("http://{}/".format(options.ip_port))
        while True:
            filename = req.nextFileName()
            if filename is None:
                break

            try:
                (reference_functions,
                pre_sweep_functions,
                post_sweep_functions,
                false_negatives,
                false_positives,
                possible_missed,
                seconds) = run_test(filename)
                print "reference_functions ", reference_functions
                print "pre_sweep_functions ", pre_sweep_functions
                print "post_sweep_functions ", post_sweep_functions
                print "false_negatives ", false_negatives
                print "false_positives ", false_positives
                print "possible_missed ", possible_missed
                print "seconds ", seconds

                req.reportResult(filename,
                                 reference_functions,
                                 pre_sweep_functions,
                                 post_sweep_functions,
                                 false_negatives,
                                 false_positives,
                                 possible_missed,
                                 seconds)
            except KeyboardInterrupt:
                break
    else:
        for i, filename in enumerate(args):
            try:
                (reference_functions,
                pre_sweep_functions,
                post_sweep_functions,
                false_negatives,
                false_positives,
                possible_missed,
                seconds) = run_test(filename)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print e
                continue

            total_ref += reference_functions
            total_fp += len(false_positives)
            total_fn += len(false_negatives)
            total_found += post_sweep_functions - pre_sweep_functions

            # Now we have all the information needed for our record
            print "{seconds}s Complete: %{complete} File: {filename} TotalRefFunctions: {reference} PostSweep: {psf} SweepFound: {found} FalsePositives: {fp} %{fpp:.2f} FalseNegatives: {fn} %{fnp:.2f} FNs {fns}, FPs {fps} PossibleMissed {missed}".format(
                filename=filename,
                reference=reference_functions,
                psf=post_sweep_functions,
                found=post_sweep_functions - pre_sweep_functions,
                fp=len(false_positives), fpp=100 * (len(false_positives) / float(reference_functions)),
                fn=len(false_negatives), fnp=100 * (len(false_negatives) / float(reference_functions)),
                fns=str(map(hex, false_negatives)), fps=str(map(hex, false_positives)),
                complete=int(100 * (float(i) / len(args))),
                seconds=seconds,
                missed=possible_missed)

        if total_ref > 0:
            print ("Overall Total Functions: {total_ref}\n"
                "Overall Functions found: {total_found} %{pfnd:.2f}\n"
                "Overall False Positives: {total_fp} %{pfp:.2f}\n"
                "Overall False Negatives: {total_fn} %{pfn:.2f}\n").format(
                    total_ref=total_ref,
                    total_found=total_found, pfnd=(100 * total_found / float(total_ref)),
                    total_fp=total_fp, pfp=(100 * total_fp / float(total_ref)),
                    total_fn=total_fn, pfn=(100 * total_fn / float(total_ref)))
        else:
            print ("finished without analyzing anything")


if __name__ == "__main__":
    main()
