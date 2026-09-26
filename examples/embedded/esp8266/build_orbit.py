from pathlib import Path
Import("env")
root = Path(env["PROJECT_DIR"]).resolve().parents[2]
sdk = root / "sdk" / "embedded"
framework = Path(env.PioPlatform().get_package_dir("framework-arduinoespressif8266"))
env.Append(CFLAGS=["-std=c11"], CPPPATH=[
    str(framework / "libraries/ESP8266WiFi/src"),
    str(framework / "libraries/LittleFS/src"),
])
env.Append(LIBS=[
    env.BuildLibrary("$BUILD_DIR/orbit-core", str(sdk / "src")),
    env.BuildLibrary("$BUILD_DIR/orbit-adapters", str(sdk / "adapters"), src_filter=[
        "+<http.c>", "+<platform.c>", "+<bearssl.c>", "+<esp8266.cpp>"]),
    env.BuildLibrary("$BUILD_DIR/orbit-example", str(root / "examples" / "embedded" / "common")),
])
