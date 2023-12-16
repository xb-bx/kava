curl https://raw.githubusercontent.com/xb-bx/nobuild.odin/master/nobuild.odin > nobuild.odin
odin build . -out:build.exe


$vswhereOutput = & 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$match = echo $vswhereOutput | Select-String -Pattern "installationPath: (.*)"
$envVarsPath = $match.Matches[0].Groups[1].Value + "\VC\Auxiliary\Build\vcvars64.bat"
cmd /c "$envVarsPath & build.exe"

