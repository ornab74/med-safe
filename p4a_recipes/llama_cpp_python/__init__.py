from pythonforandroid.recipe import CMakePythonRecipe


class LlamaCppPythonRecipe(CMakePythonRecipe):
    """
    Custom python-for-android recipe that builds llama-cpp-python
    for Android using CMake.

    It corresponds to the pip package "llama-cpp-python", but the
    recipe name is "llama_cpp_python" (underscores), which is what
    we use in buildozer.spec requirements.
    """

    # Pick a version that works for you; keep in sync with the model code.
    version = "0.3.0"
    url = "https://github.com/abetlen/llama-cpp-python/archive/refs/tags/v{version}.zip"

    # p4a "logical" name; MUST match buildozer.spec requirements
    name = "llama_cpp_python"

    # Base dependencies
    depends = ["python3"]
    python_depends = []

    # Python import / site-packages name
    site_packages_name = "llama_cpp_python"

    # Don’t run hostpython under targetpython wrapper
    call_hostpython_via_targetpython = False

    # Install into site-packages on the target
    install_in_site_packages = True

    def get_cmake_args(self, arch):
        """
        Extra CMake flags to make the build more Android-friendly:
        - disable GPU backends
        - disable tests/examples
        - set Android ABI + platform
        """
        args = [
            "-DCMAKE_BUILD_TYPE=Release",
            "-DLLAMA_CUBLAS=OFF",
            "-DLLAMA_CLBLAST=OFF",
            "-DLLAMA_METAL=OFF",
            "-DLLAMA_OPENBLAS=OFF",
            "-DLLAMA_ACCELERATE=OFF",
            "-DLLAMA_F16C=OFF",
            "-DLLAMA_NATIVE=OFF",
            "-DLLAMA_BUILD_EXAMPLES=OFF",
            "-DLLAMA_BUILD_TESTS=OFF",
            # Android target
            f"-DANDROID_ABI={arch.arch}",
            f"-DANDROID_PLATFORM=android-{self.ctx.ndk_api}",
        ]
        return args


recipe = LlamaCppPythonRecipe()
