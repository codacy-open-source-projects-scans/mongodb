"""
Script to extract features from failed queries stored in .fail files generated by a
QueryTester run with the <--mode compare> option. This script automates the process of:

1. Reading queries from .fail files.
2. Running feature extraction on those queries.
3. Converting extracted features into JSON format.
4. Loading the features from JSON into an aggregate DataFrame.
5. Saving the processed DataFrame to a pickle file (.pkl).
6. Cleaning up intermediate results (e.g., temporary JSON files).

This script facilitates the analysis of failed queries by converting them into a structured format
that can be further analyzed or processed within the QueryTester framework.
"""

import subprocess

import utils

# Parse and validate arguments
args = utils.parse_args_common(
    "Extract features from QueryTester .fail files into an aggregate pickle file.",
    fail_filepath=True,
)
output_prefix = args.output_prefix
fail_filepath = args.fail_filepath

# Validate directories and change to feature-extractor directory
feature_extractor_dir = utils.validate_and_change_directory(args.feature_extractor_dir)

# Validate fail_filepath
utils.validate_fail_filepath(fail_filepath)

# Run extraction with mongosh
pkl_file, json_file = utils.construct_filenames(output_prefix, fail_filepath.stem)
bash_command = (
    f"cat {fail_filepath} | python extract_from_test.py | mongosh --nodb --quiet > {json_file}"
)
subprocess.run(bash_command, shell=True, text=True, check=True)

# Extract DB and COLL from the .fail file
db, coll = utils.extract_db_and_coll(fail_filepath)

# Convert JSON into DataFrame, passing in the relevant DB and COLL.
cmd = [
    "bin/venv",
    "extract_features_to_dataframe.py",
    "--uri",
    utils.MONGODB_URI,
    "--db",
    db,
    "--coll",
    coll,
]
with open(json_file, encoding="utf-8") as json_input:
    with open(pkl_file, "ab") as pkl_output:
        subprocess.run(cmd, stdin=json_input, stdout=pkl_output, check=True)

# Clean up JSON file after we finish processing
utils.clean_up_file(json_file, "Intermediate JSON file")
print("Process completed successfully.")