# action-checksec

This action runs checksec.sh on ELF and winchecksec on PE binaries and reports any missing compilation flags that should be enabled as either errors or warnings. If there are any errors it returns non zero, failing the job. If `GITHUB_TOKEN` and `GITHUB_COMMENT_URL` is passed as `env` variables the action will report on the PR as comments. The table of all flags can be disabled by setting the input `print_flag_table` to `"off"`.

Example workflow building on windows and then running winchecksec on artifacts.

Note: the only ubuntu version it runs on is ubuntu-20.04 for now.


```name: windows
on: [push, pull_request]
jobs:
  build:
    runs-on: windows-latest
    steps:
    - uses: actions/checkout@v1
    - name: build
      run: |
        cmake . -G "Visual Studio 16 2019" -A x64
        cmake --build . --verbose

    - uses: nevun/action-checksec@master
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        GITHUB_COMMENT_URL: ${{ github.event.pull_request.comments_url }}
      with:
        executables: |
          "Debug/test.exe"
          "Debug/more_test.exe"
        libraries: |
          "Debug/foo.dll"
```

`executables`, `libraries` and `verbose` are optional inputs.

If you pass the GITHUB_TOKEN and GITHUB_COMMENT_URL as env variables the action will also post comments on a PR instead of just in the job log.

If the action fails on windows it might be because it has a hardcoded path to python 3.9.0 in the hosted tool cache.

As a workaround until the action gets updated, add this above `uses: nevun/action-checksec`:

```
    - uses: actions/setup-python@v2
      with:
        python-version: '3.9.x'
```
