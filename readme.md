# MCP Bridge

This repository contains the `bridge_mcp.py` script. Follow the steps below to set up the environment, install the required Python packages, and run the script.
It should be used first the script `results_parser.py` to read the sarif/json file with the results so they're parsed and saved in a sqlite database.

## Prerequisites

- Python 3.7 or higher installed on your system.
- `venv` module available (comes with Python by default).

## Installation

1. **Clone the Repository**  
    Clone this repository to your local machine:
    ```bash
    git clone <repository-url>
    cd mcp_bridge
    ```

2. **Create a Virtual Environment**  
    Create a virtual environment named `env`:
    ```bash
    python -m venv env
    ```

3. **Activate the Virtual Environment**  
    - On Windows:
      ```bash
      .\env\Scripts\activate
      ```
    - On macOS/Linux:
      ```bash
      source env/bin/activate
      ```

4. **Install Required Packages**  
    Install the dependencies listed in `requirements.txt`:
    ```bash
    pip install -r requirements.txt
    ```

## Running the Script

1. Ensure the virtual environment is activated:
    ```bash
    .\env\Scripts\activate  # Windows
    source env/bin/activate  # macOS/Linux
    ```

2. Run the `bridge_mcp.py` script:
    ```bash
        python bridge_mcp.py
        ```

        ## Script Options

        The `bridge_mcp.py` script supports several command-line options:

        - `--mcp-host`  
            Host to run MCP server on (only used for SSE). Default: `127.0.0.1`.

        - `--mcp-port`  
            Port to run MCP server on (only used for SSE). Default: `8081`.

        - `--transport`  
            Transport protocol for MCP. Choices: `stdio`, `sse`. Default: `stdio`.

        - `--database`  
            The name of the SQLite3 database to be read. Default: `DEFAULT_DB`.

        - `--source-folder`  
            The folder of the project's source code in the input folder. Default: `openmrs-core-2.6.2`.

        Example usage:
        ```bash
        python bridge_mcp.py --mcp-host 192.168.1.100 --mcp-port 8081 --transport sse --database results.db --source-folder my_project
        ```

## Deactivating the Environment

When you're done, deactivate the virtual environment:
```bash
deactivate
```

## Notes

- Make sure to update `requirements.txt` if additional dependencies are added.
- For troubleshooting, ensure all dependencies are installed correctly and the Python version is compatible.
- This mcp bridge can be configured with [Copilot Chat Agent mode](https://code.visualstudio.com/blogs/2025/05/12/agent-mode-meets-mcp)
    - TLDR; Open .vscode/mcp.json in vscode and click "Add Server".
