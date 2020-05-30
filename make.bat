@cd src
@call make.bat
@cd ..

@mkdir build64msvc
@cd build64msvc
@conan install .. -s compiler.version=15 -s compiler.runtime=MT -s compiler.toolset=v141_xp -s arch=x86_64 -s build_type=Release --build=missing
@cmake -G "Visual Studio 15 2017 Win64" ..
@"C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\MSBuild\15.0\Bin\MSBuild.exe" ARX.sln /p:MultiProcessorCompilation=true /p:CL_MPCount=8  /p:Platform="x64" /p:Configuration=RelWithDebInfo /p:BuildInParallel=true /m:8 /maxcpucount:8
@cd ..