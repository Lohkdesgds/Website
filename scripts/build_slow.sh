echo "Building..."

cd ..
mkdir build
cd ./build

echo "Preparing to build..."

cmake ..

echo "Making build..."

make -j2

cp -T ./website ./release-website

echo "The end!"
