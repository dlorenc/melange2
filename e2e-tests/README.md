# e2e-tests
.yaml files in this directory will be built by melange2 via
the 'run-tests' script.

Melange2 options are based on yaml file name.

 * `*-build.yaml`: run 'melange2 build'
 * `*-test.yaml`: run 'melange2 test'
 * `*-build-test`: run 'melange2 build && melange2 test'

    If the yaml file name matches '*-nopkg', then the flag `--test-package-append`
    will be appended for `busybox` and `python-3`.  The intent of these tests
    is to verify that the test-package-append works.
