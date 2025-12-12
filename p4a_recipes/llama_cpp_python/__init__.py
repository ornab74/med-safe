import os

from pythonforandroid.recipe import PythonRecipe
from pythonforandroid.toolchain import current_directory, shprint
import sh


class LlamaCppPythonRecipe(PythonRecipe):
    """
    Custom recipe to build llama-cpp-python for Android.

    NOTE:
      - We subclass PythonRecipe (available in all recent p4a versions),
        NOT CMakePythonRecipe (which your version doesn’t have).
      - We override get_recipe_env to inject CMake / Android flags so the
        package’s own CMakeLists can try to cross-compile for Android.
      - This is a best-effort starting point; you may still need to tune
        flags if CMake complains in later steps.
    """

    name = "llama_cpp_python"
    version = "0.2.83"  # pick any version you like
    url = "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/v{version}.tar.gz"

    # Keep it light: setuptools + wheel + numpy if needed
    depends = ["setuptools", "wheel"]

    # Let targetpython run pip directly
    call_hostpython_via_targetpython = False

    def get_recipe_env(self, arch):
        # Start from the default env
        env = super().get_recipe_env(arch)

        # Paths / versions from the p4a context
        ndk_dir = self.ctx.ndk_dir
        api = self.ctx.ndk_api

        # llama-cpp-python respects these environment variables
        # when building with CMake
        env["FORCE_CMAKE"] = "1"

        # Generic CMake Android config
        env["CMAKE_SYSTEM_NAME"] = "Android"
        env["CMAKE_ANDROID_NDK"] = ndk_dir
        env["CMAKE_SYSTEM_VERSION"] = str(api)
        env["CMAKE_ANDROID_ARCH_ABI"] = arch.arch
        env["CMAKE_ANDROID_STL_TYPE"] = "c++_static"

        # Disable GPU / BLAS backends to simplify the build
        env["LLAMA_CUBLAS"] = "0"
        env["LLAMA_CLBLAST"] = "0"
        env["LLAMA_METAL"] = "0"
        env["LLAMA_OPENBLAS"] = "0"
        env["LLAMA_BLAS"] = "0"

        # This can help CMake find the toolchain
        env["ANDROID_NDK"] = ndk_dir
        env["ANDROIDAPI"] = str(api)

        return env

    def build_arch(self, arch):
        """
        We just reuse PythonRecipe's build_arch, which uses pip to build
        the extension, but with our tweaked env above.
        """
        # Optional: debug info
        build_dir = self.get_build_dir(arch)
        shprint(sh.echo, f"[llama_cpp_python] building in {build_dir} for {arch.arch}")
        super().build_arch(arch)


recipe = LlamaCppPythonRecipe()
