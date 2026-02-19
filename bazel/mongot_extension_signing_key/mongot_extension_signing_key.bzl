"""Rules for downloading and embedding mongot_extension_signing_key"""

# This is the mongot-extension's signing public key. It is managed by garasign, and used by the
# SignatureValidator in secure builds (i.e MONGO_CONFIG_EXT_SIG_SECURE) to verify the authenticity
# of extensions before loading them into the server process. Whenever the remote file changes, the
# corresponding sha256 must be changed.

def _impl(ctx):
    ctx.download(
        url = "https://pgp.mongodb.com/mongot-extension.pub",
        sha256 = "2a15e6a2d9f6c0d8141dad515d9360f6cf01e1a11f7e2c3bc0820e18c5e9d0b7",
        output = "mongot-extension.pub",
    )
    ctx.file("BUILD.bazel", 'exports_files(["mongot-extension.pub"])')

mongot_extension_signing_key_repo = repository_rule(implementation = _impl)

def mongot_extension_signing_key():
    mongot_extension_signing_key_repo(name = "mongot_extension_signing_key")

def _gpg_export_armored_key_impl(ctx):
    key = ctx.file.key
    armored_key_output_file = ctx.outputs.armored_key_output_file
    pass_file = ctx.file.passphrase

    # Collect tool files from the filegroups
    bin_files = ctx.attr.gpg_bins.files.to_list()
    lib_files = ctx.attr.gpg_libs.files.to_list()

    # Find the gpg executable
    gpg_bin = None
    for f in bin_files:
        if f.basename == "gpg":
            gpg_bin = f
            break
    if gpg_bin == None:
        fail("gpg binary not found in @gpg//:gpg_bins")

    # Compute libs dir next to the bundle’s bin dir:
    # …/gpg_bundle-*/bin/gpg -> …/gpg_bundle-*/libs
    p = gpg_bin.path
    bin_dir = p[:p.rfind("/")]
    bundle_dir = bin_dir[:bin_dir.rfind("/")]
    libs_dir = bundle_dir + "/libs"

    # Arguments your Python helper expects: <gpg> <key> <passphrase_or_empty> <armored_key_output_file>
    args = [
        gpg_bin.path,
        key.path,
        pass_file.path if pass_file else "",
        armored_key_output_file.path,
    ]

    # Create the action; stage bins/libs as tools for the exec platform
    ctx.actions.run(
        executable = ctx.executable.script,
        arguments = args,
        inputs = [key] + ([pass_file] if pass_file else []),
        tools = bin_files + lib_files + [ctx.executable.script],
        outputs = [armored_key_output_file],
        env = {"LD_LIBRARY_PATH": libs_dir},
        mnemonic = "GpgExportArmored",
        progress_message = "Export armored key to %s" % armored_key_output_file.path,
    )

gpg_export_armored_key = rule(
    implementation = _gpg_export_armored_key_impl,
    attrs = {
        "key": attr.label(allow_single_file = True, mandatory = True),
        "passphrase": attr.label(allow_single_file = True),
        "armored_key_output_file": attr.output(mandatory = True),
        "script": attr.label(
            default = Label("//bazel/mongot_extension_signing_key:gpg_export_armored_key"),
            executable = True,
            cfg = "exec",
        ),
        # Treat these as tools (exec config)
        "gpg_bins": attr.label(
            default = Label("@gpg//:gpg_bins"),
            allow_files = True,
            cfg = "exec",
        ),
        "gpg_libs": attr.label(
            default = Label("@gpg//:gpg_libs"),
            allow_files = True,
            cfg = "exec",
        ),
    },
)
