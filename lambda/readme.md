## Installing Dependencies
```
git clone https://github.com/awslabs/aws-lambda-cpp /tmp/aws-lambda-cpp
cd /tmp/aws-lambda-cpp
mkdir build; cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=$HOME/pka2xml/lambda-runtime
```

## Building
```
mkdir build; cd build
cmake .. -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=../lambda-runtime \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
    -DBUILD_SHARED_LIBS=ON
```
