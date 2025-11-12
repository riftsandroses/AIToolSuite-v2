import subprocess
import tempfile
import os
import logging
import shutil

logger = logging.getLogger(__name__)

def render_mermaid_to_image(mermaid_code):
    """
    Renders MermaidJS code to a PNG image using the Mermaid CLI.

    Args:
        mermaid_code (str): The string containing the MermaidJS diagram syntax.

    Returns:
        str: The file path to the generated PNG image, or None if rendering fails.
    """
    infile_path, outfile_path = None, None
    try:
        # --- Write Mermaid code to a temp .mmd file ---
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.mmd') as infile:
            infile.write(mermaid_code)
            infile_path = infile.name
        outfile_path = infile_path.replace(".mmd", ".png")

        logger.debug(f"Mermaid code written to temp file: {infile_path}")
        logger.debug(f"Expected output image path: {outfile_path}")

        # --- Locate mmdc executable ---
        mmdc_path = shutil.which("mmdc")
        logger.debug(f"Resolved mmdc path: {mmdc_path}")
        if not mmdc_path:
            logger.error("Mermaid CLI ('mmdc') not found in PATH.")
            return None

        # --- Build command ---
        command = [
            mmdc_path,
            "-i", infile_path,
            "-o", outfile_path,
            "-w", "1024",
            "-b", "transparent"
        ]
        logger.info(f"Executing Mermaid CLI command: {' '.join(command)}")

        # --- Run the command and capture logs ---
        result = subprocess.run(command, capture_output=True, text=True)
        logger.debug(f"mmdc return code: {result.returncode}")
        if result.stdout:
            logger.debug(f"mmdc stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.debug(f"mmdc stderr: {result.stderr.strip()}")

        if result.returncode != 0:
            logger.error(f"Mermaid CLI failed with code {result.returncode}. See logs above.")
            return None

        if not os.path.exists(outfile_path):
            logger.error("Mermaid CLI reported success but PNG file not found.")
            return None

        logger.info(f"Successfully rendered Mermaid diagram to: {outfile_path}")
        return outfile_path

    except Exception as e:
        logger.exception(f"Unexpected error in render_mermaid_to_image: {e}")
        return None
    finally:
        # --- Cleanup input file ---
        if infile_path and os.path.exists(infile_path):
            try:
                os.remove(infile_path)
                logger.debug(f"Cleaned up temp input file: {infile_path}")
            except Exception as cleanup_err:
                logger.warning(f"Failed to delete temp input file {infile_path}: {cleanup_err}")
