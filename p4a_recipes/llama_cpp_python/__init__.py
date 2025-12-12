import os
from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory
from pythonforandroid.logger import info, shprint
import sh


class LlamaCppPythonRecipe(Recipe):
    name = "llama_cpp_python"
    version = "0.3.2"

    # Exact 0.3.2 sdist URL (avoids 404 from wrong /packages/source/... path)
    url = "https://files.pythonhosted.org/packages/5f/0e/ff129005a33b955088fc7e4ecb57e5500b604fb97eca55ce8688dbe59680/llama_cpp_python-0.3.2.tar.gz"

    depends = ["python3"]
    python_depends = []

    # Top-level import is llama_cpp
    site_packages_name = "llama_cpp"

    call_hostpython_via_targetpython = False

    def _host_tools_env(self, base_env: dict) -> dict:
        """
        pip-install build tooling in a *host* env.
        Do NOT leak Android cross-compile CC/CFLAGS into this step.
        """
        env = dict(base_env)

        # Remove common cross-compile variables p4a sets
        for k in (
            "CC", "CXX", "AR", "AS", "LD", "STRIP", "RANLIB",
            "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
            "PKG_CONFIG", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR",
        ):
            env.pop(k, None)

        # Ensure user site is enabled (pip may default to --user if site-packages isn't writable)
        env["PYTHONNOUSERSITE"] = "0"
        return env

    def get_recipe_env(self, arch):
        env = super().get_recipe_env(arch)

        cmake_args = env.get("CMAKE_ARGS", "")

        # llama-cpp-python forwards llama.cpp options via CMAKE_ARGS :contentReference[oaicite:1]{index=1}
        cmake_args += " -DLLAMA_BUILD_EXAMPLES=OFF"
        cmake_args += " -DLLAMA_BUILD_TESTS=OFF"
        cmake_args += " -DLLAMA_BUILD_SERVER=OFF"

        # Android/CPU-friendly
        cmake_args += " -DGGML_OPENMP=OFF"
        cmake_args += " -DGGML_LLAMAFILE=OFF"
        cmake_args += " -DGGML_NATIVE=OFF"

        cmake_args += " -DGGML_CUDA=OFF"
        cmake_args += " -DGGML_VULKAN=OFF"
        cmake_args += " -DGGML_OPENCL=OFF"
        cmake_args += " -DGGML_METAL=OFF"

        # Make build logs much louder
        cmake_args += " -DCMAKE_VERBOSE_MAKEFILE=ON"

        # Optional: modern ARM64 tuning (only for arm64)
        if getattr(arch, "arch", None) == "arm64-v8a":
            cmake_args += ' -DCMAKE_C_FLAGS="-march=armv8.7a"'
            cmake_args += ' -DCMAKE_CXX_FLAGS="-march=armv8.7a"'

        env["CMAKE_ARGS"] = cmake_args.strip()

        # Keep user-site enabled
        env["PYTHONNOUSERSITE"] = "0"

        # Reduce “implicit *” warnings killing the build under strict flags
        for k in ("CFLAGS", "CXXFLAGS"):
            env[k] = (env.get(k, "") + " -Wno-error=implicit-function-declaration -Wno-error=implicit-int").strip()

        # Helps for some llama-cpp-python builds
        env.setdefault("FORCE_CMAKE", "1")

        # scikit-build-core respects CMAKE_ARGS; verbose helps debug :contentReference[oaicite:2]{index=2}
        env.setdefault("SKBUILD_VERBOSE", "1")

        return env

    def build_arch(self, arch):
        info(f"[llama_cpp_python] building for arch {arch}")

        target_env = self.get_recipe_env(arch)
        build_dir = self.get_build_dir(arch)
        hostpython_cmd = sh.Command(self.ctx.hostpython)

        # Put all pip-installed tooling in a writable per-arch userbase
        userbase = os.path.join(build_dir, "_hostpython_userbase")
        os.makedirs(userbase, exist_ok=True)
        target_env["PYTHONUSERBASE"] = userbase

        host_env = self._host_tools_env(target_env)
        host_env["PYTHONUSERBASE"] = userbase

        with current_directory(build_dir):
            # 1) Ensure pip exists (hostpython often has no pip)
            # ensurepip is the stdlib way to bootstrap pip :contentReference[oaicite:3]{index=3}
            info("[llama_cpp_python] bootstrapping pip via ensurepip")
            shprint(hostpython_cmd, "-m", "ensurepip", "--upgrade", "--default-pip", _env=host_env)

            # 2) Install build backends/tools needed for pyproject build
            # With --no-build-isolation, build requirements must already be present :contentReference[oaicite:4]{index=4}
            info("[llama_cpp_python] installing build backends/tools (host env)")
            shprint(
                hostpython_cmd,
                "-m", "pip", "install",
                "--user",
                "--upgrade",
                "pip",
                "setuptools",
                "wheel",
                "cmake",
                "ninja",
                "typing_extensions",
                "numpy==1.26.4",
                "scikit-build-core",
                "flit-core",
                _env=host_env,
            )

            # Quick sanity check for the flit backend import
            shprint(hostpython_cmd, "-c", "import flit_core.buildapi; print('flit_core OK')", _env=host_env)

            # 3) Build + install package for target (verbose, no deps)
            # (p4a generally prefers handling deps itself; --no-deps avoids extra noise)
            info("[llama_cpp_python] building+installing (target env, very verbose)")
            shprint(
                hostpython_cmd,
                "-m", "pip", "install",
                "--user",
                "-vvv",
                ".",
                "--no-deps",
                "--no-binary", ":all:",
                "--no-build-isolation",
                _env=target_env,
            )


recipe = LlamaCppPythonRecipe()
