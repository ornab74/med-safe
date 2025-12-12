import os
from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(Recipe):
    name = "llama_cpp_python"
    version = "0.3.2"

    # Exact 0.3.2 sdist URL (avoids /packages/source/... naming pitfalls)
    url = "https://files.pythonhosted.org/packages/5f/0e/ff129005a33b955088fc7e4ecb57e5500b604fb97eca55ce8688dbe59680/llama_cpp_python-0.3.2.tar.gz"

    depends = ["python3"]
    python_depends = []

    # Top-level import is llama_cpp
    site_packages_name = "llama_cpp"

    call_hostpython_via_targetpython = False

    def get_recipe_env(self, arch):
        env = super().get_recipe_env(arch)

        cmake_args = env.get("CMAKE_ARGS", "")

        cmake_args += " -DLLAMA_BUILD_EXAMPLES=OFF"
        cmake_args += " -DLLAMA_BUILD_TESTS=OFF"
        cmake_args += " -DLLAMA_BUILD_SERVER=OFF"

        cmake_args += " -DGGML_OPENMP=OFF"
        cmake_args += " -DGGML_LLAMAFILE=OFF"
        cmake_args += " -DGGML_NATIVE=OFF"

        cmake_args += " -DGGML_CUDA=OFF"
        cmake_args += " -DGGML_VULKAN=OFF"
        cmake_args += " -DGGML_OPENCL=OFF"
        cmake_args += " -DGGML_METAL=OFF"

        if getattr(arch, "arch", None) == "arm64-v8a":
            cmake_args += ' -DCMAKE_C_FLAGS="-march=armv8.7a"'
            cmake_args += ' -DCMAKE_CXX_FLAGS="-march=armv8.7a"'

        env["CMAKE_ARGS"] = cmake_args.strip()

        # Keep user-site enabled so user installs are importable (PYTHONNOUSERSITE disables it). :contentReference[oaicite:2]{index=2}
        env["PYTHONNOUSERSITE"] = "0"

        # Reduce “warnings as errors” pain from p4a defaults
        for k in ("CFLAGS", "CXXFLAGS"):
            env[k] = (env.get(k, "") + " -Wno-error=implicit-function-declaration -Wno-error=implicit-int").strip()

        # Prefer cmake build path in llama-cpp-python
        env.setdefault("FORCE_CMAKE", "1")

        return env

    def build_arch(self, arch):
        info(f"[llama_cpp_python] building for arch {arch}")

        env = self.get_recipe_env(arch)
        build_dir = self.get_build_dir(arch)

        hostpython_cmd = sh.Command(self.ctx.hostpython)

        # Put all pip-installed build tools in a writable, per-arch location
        userbase = os.path.join(build_dir, "_hostpython_userbase")
        os.makedirs(userbase, exist_ok=True)
        env["PYTHONUSERBASE"] = userbase  # user base can be overridden this way. :contentReference[oaicite:3]{index=3}

        with current_directory(build_dir):
            # 1) Bootstrap pip into this Python (hostpython may not have pip). :contentReference[oaicite:4]{index=4}
            info("[llama_cpp_python] ensure pip via ensurepip")
            shprint(hostpython_cmd, "-m", "ensurepip", "--upgrade", "--default-pip", _env=env)

            # 2) Install build tools into our userbase (writable)
            info("[llama_cpp_python] installing build tools into PYTHONUSERBASE")
            shprint(
                hostpython_cmd,
                "-m", "pip", "install",
                "--user",
                "--upgrade",
                "pip",
                "setuptools",
                "wheel",
                "scikit-build-core",
                "cmake",
                "ninja",
                "typing_extensions",
                "numpy==1.26.4",
                "flit-core",
                _env=env,
            )

            # 3) Build + install llama-cpp-python from source (verbose)
            info("[llama_cpp_python] building and installing from source (verbose)")
            shprint(
                hostpython_cmd,
                "-m", "pip", "install",
                "--user",
                "-v",
                ".",
                "--no-binary", ":all:",
                "--no-build-isolation",
                _env=env,
            )


recipe = LlamaCppPythonRecipe()
