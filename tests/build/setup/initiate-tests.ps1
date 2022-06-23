# Invoke Pester to run  tests, then save the results in NUnitXML to populate the AppVeyor tests section
# Pester               : https://github.com/pester/Pester/wiki
# Pester Code Coverage : https://info.sapien.com/index.php/scripting/scripting-modules/testing-pester-code-coverage

Import-Module Pester -RequiredVersion '4.9.0'
New-Item -Path .\tests -Name results -ItemType Directory -Force

$testResultPath = '.\tests\build\results\TestResults.xml'
# This is a manifest so no code coverage is possible.  Original line kept below:
#...\results\TestsResults.xml -PassThru -CodeCoverage .\MSFTNetworking.Tools.psd1
$res = Invoke-Pester -Path ".\tests\build\unit" -OutputFormat NUnitXml -OutputFile $testResultPath -PassThru

(New-Object 'System.Net.WebClient').UploadFile("https://ci.appveyor.com/api/testresults/nunit/$($env:APPVEYOR_JOB_ID)", (Resolve-Path $testResultPath))

If ($res.FailedCount -gt 0) { throw "$($res.FailedCount) tests failed." }
