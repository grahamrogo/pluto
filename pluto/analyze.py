import subprocess
import logging

def run_sleuthkit_analysis(image_path, output_report):
    """
    Runs Sleuth Kit tools (fsstat and fls) on a partition image and outputs a consolidated report.

    Args:
        image_path (str): Path to the partition image.
        output_report (str): Path to the file where the analysis report will be saved.
    """
    try:
        logging.info(f"Starting Sleuth Kit analysis on partition image: {image_path}")

        # Commands to run fsstat and fls
        commands = {
            "Filesystem Metadata (fsstat)": ["fsstat", "-f", "ext4", image_path],
            "File Listing (fls)": ["fls", image_path],
        }

        # Write the results to the output report
        with open(output_report, "w") as report_file:
            report_file.write("=== Sleuth Kit Analysis Report ===\n\n")
            for title, command in commands.items():
                report_file.write(f"=== {title} ===\n")
                logging.info(f"Running: {title}")
                try:
                    result = subprocess.run(
                        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
                    )
                    report_file.write(result.stdout + "\n")
                except subprocess.CalledProcessError as e:
                    error_message = f"Error running {title}: {e.stderr}\n"
                    report_file.write(error_message)
                    logging.error(error_message)

        logging.info(f"Analysis report saved to: {output_report}")

    except Exception as e:
        logging.error(f"Error during Sleuth Kit analysis: {e}")
        raise
