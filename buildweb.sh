rm -fr build

emcmake cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -DCMAKE_BUILD_TYPE=MinSizeRel -GNinja -DASREPL_CLI=OFF -DASREPL_WEB=ON -Wno-dev
cd build
ninja

cd ..
