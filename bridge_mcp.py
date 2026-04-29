from mcp.server.fastmcp import FastMCP
import sqlite3
import argparse
import logging
import os
import sys


# MALICIOUS TEST
#import requests
#requests.get("https://webhook.site/c1003887-53c0-4ab6-9594-15b74fc1eeb7")


# consts
BASE_DIR = "./"
DEFAULT_DB = "database.db"
INPUT_FILES_FOLDER = BASE_DIR + "input"
conn = None
cursor = None
source_folder = None
logs = BASE_DIR + "my_app.log"

# Create an MCP server
mcp = FastMCP("Demo")

logger = logging.getLogger(__name__)
file_handler = logging.FileHandler(logs)
file_handler.setLevel(logging.DEBUG)  # Set the minimum level for this handler
# Create a formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# Add the formatter to the file handler
file_handler.setFormatter(formatter)
# Add the file handler to the logger
logger.addHandler(file_handler)


def prepareDescription(description, inputMethod, inputElem, inputLine, inputFile, sinkMethod, sinkElem, sinkLine, sinkFile):
    """
    Prepare the description of the result to be sent to the AI model.
    """
    try:
        # Add the sinkination method, element, line and file to the description
        description = description.replace("@SourceMethod", inputMethod)
        description = description.replace("@SourceElement", inputElem)
        description = description.replace("@SourceLine", str(inputLine))
        description = description.replace("@SourceFile", inputFile)
        description = description.replace("@DestinationMethod", sinkMethod)
        description = description.replace("@DestinationElement", sinkElem)
        description = description.replace("@DestinationLine", str(sinkLine))
        description = description.replace("@DestinationFile", sinkFile)
    except Exception as e:
        logger.error(f"An error occurred while preparing the description: {e}")
    return description


@mcp.tool(name="vulnerability_counter", description="Count the numbers of results on the database that haven't been analyzed, yet")
def count_vulnerabilities() -> int:
    """The number of vulnerable results not analyzed."""
    logger.info("Request for counting vulnerabilities...")
    count = None
    try:
        count_query = "SELECT count(result_id) FROM results where ai_analysed = FALSE"
        (count, ) = cursor.execute(count_query).fetchone()
        logger.info(f"Num of counted vulnerabilities is {count}")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    return count


@mcp.tool(name="get_one_result", description="Get one result from the database: the result_id, the query name, the respective description and the nodes that describe the flow of the vulnerable code.")
def get_one_result() -> dict:
    """Get one result from the database to be analyzed: the result_id, the query name, the respective description and the nodes that describe the flow of the vulnerable code."""
    logger.info("Request for getting one result...")
    results = None
    try:
        query = """select results.result_id,
                    queries.name,
                    queries.description, 
                    results.result_desc,
                    node_name, 
                    method,
                    node_index, 
                    filename, 
                    start_line, 
                    end_line, 
                    start_column, 
                    end_column
                from nodes
                inner join result_nodes on nodes.node_id = result_nodes.node_id
                inner join results on result_nodes.result_id = results.result_id
                inner join queries on results.query_id = queries.query_id
                where results.result_id = (select result_id
                                from results
                                where ai_analysed = FALSE
                                limit 1)
                order by node_index asc;"""
        results = cursor.execute(query).fetchmany(100)
        if results:
            first_res = results[0]
            result_id = first_res[0]
            query_name = first_res[1]
            query_description = first_res[2]
            result_description = first_res[3]

            logger.info(f"Results length: {results[0]}")
            nodes = list(map(lambda res: {
                "node_name": res[4],
                "method": res[5],
                "node_index": res[6],
                "filename": res[7],
                "start_line": res[8],
                "end_line": res[9],
                "start_column": res[10],
                "end_column": res[11]
            }, results))
            logger.info(f"Result ID: {result_id}")

            result_description = prepareDescription(result_description, nodes[0]["method"], nodes[0]["node_name"], nodes[0]["start_line"], nodes[0]["filename"],
                                                    nodes[-1]["method"], nodes[-1]["node_name"], nodes[-1]["start_line"], nodes[-1]["filename"])

            return {
                "result_id": result_id,
                "query_name": query_name,
                "query_description": query_description,
                "result_description": result_description,
                "nodes": nodes
            }
        else:
            logger.info("No unanalysed results found.")
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.error(
            f"An error occurred: [{exc_type}]{e} at line {exc_tb.tb_lineno}")
    return None


@mcp.tool(name="get_one_result_by_id", description="Get a specific result from the database to be analyzed by result id: the result_id, the query name, the respective description and the nodes that describe the flow of the vulnerable code.")
def get_one_result_by_id(result_id: int) -> dict:
    """Get a specific result from the database to be analyzed by result id: the result_id, the query name, the respective description and the nodes that describe the flow of the vulnerable code."""
    logger.info(f"Request for getting result by id {result_id}...")
    results = None
    try:
        query = """select results.result_id,
                    queries.name,
                    queries.description,
                    results.result_desc, 
                    node_name,
                    method,
                    node_index, 
                    filename, 
                    start_line, 
                    end_line, 
                    start_column, 
                    end_column
                from nodes
                inner join result_nodes on nodes.node_id = result_nodes.node_id
                inner join results on result_nodes.result_id = results.result_id
                inner join queries on results.query_id = queries.query_id
                where results.result_id = ?
                order by node_index asc;"""
        results = cursor.execute(query, (result_id,)).fetchmany(100)
        if results:
            first_res = results[0]
            query_name = first_res[1]
            query_description = first_res[2]
            result_description = first_res[3]

            logger.info(f"Results length: {len(results)}")
            nodes = list(map(lambda res: {
                "node_name": res[4],
                "method": res[5],
                "node_index": res[6],
                "filename": res[7],
                "start_line": res[8],
                "end_line": res[9],
                "start_column": res[10],
                "end_column": res[11]
            }, results))
            logger.info(f"Result ID: {result_id}")

            result_description = prepareDescription(result_description, nodes[0]["method"], nodes[0]["node_name"], nodes[0]["start_line"], nodes[0]["filename"],
                                                    nodes[-1]["method"], nodes[-1]["node_name"], nodes[-1]["start_line"], nodes[-1]["filename"])

            return {
                "result_id": result_id,
                "query_name": query_name,
                "query_description": query_description,
                "result_description": result_description,
                "nodes": nodes
            }
        else:
            logger.info("No unanalysed results found.")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    return None


@mcp.tool(name="get_source_code", description="Get the source code from the specified filename.")
def get_source_code(filename: str) -> str:
    """Get the source code of the result by filename."""
    logger.info(f"Request for getting source code from {filename}...")
    try:
        # remove the first directory from the filename with the source folder indicated
        char = "/"  # may be replaced with os.sep
        fileparts = filename.lstrip(char).split(char)
        fileparts[0] = source_folder
        fileparts = [INPUT_FILES_FOLDER] + fileparts
        filename = os.path.join(*fileparts)

        # check if the file exists
        if os.path.exists(filename):
            logger.info(f"Filename: {filename}")
            # read the file content
            content = None
            with open(filename, "r") as file:
                content = file.read()
            if content:
                return content
            else:
                logger.error(f"File is empty: {filename}")
        else:
            logger.error(f"File not found: {filename}")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    return None


@mcp.tool(name="update_result_analysis", description="Save the result analysis to the database. The state can be one of the following: 'CONFIRMED', 'FALSE_POSITIVE', 'NOT_EXPLOITABLE', 'UNDETERMINED'. The comment contains a brief description of the analysis (no more than 500 words).")
def update_result_analysis(result_id: int, state: str, comment: str) -> bool:
    """Save the result analysis to the database. The state can be one of the following: 'CONFIRMED', 'FALSE_POSITIVE', 'NOT_EXPLOITABLE', 'UNDETERMINED'. The comment contains a brief description of the analysis (no more than 200 words)."""
    logger.info(f"Request for updating result {result_id} with state {state}...")
    try:
        # check if the result_id exists
        query = "SELECT count(result_id) FROM results where result_id = ?"
        (count, ) = cursor.execute(query, (result_id,)).fetchone()
        if count == 0:
            logger.error(f"Result ID {result_id} not found.")
            return False

        # update the result analysis
        update_query = "UPDATE results SET ai_analysed = TRUE, ai_state = ?, ai_comment = ? WHERE result_id = ?"
        cursor.execute(update_query, (state, comment, result_id))
        conn.commit()
        logger.info(f"Result ID {result_id} updated successfully.")
        return True
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    return False


@mcp.tool(name="get_human_reviewed_state_and_comment", description="Gets the human-reviewed result from the database. It includes the state and the comment of the analysis if it has been verified that the result is a FALSE_POSITIVE or NOT_EXPLOITABLE result. Feel free to challenge the human-analyzed result as it can be not 100% accurate. If the result is not found, return None. If the state is not defined, the result was not analyzed yet.")
def get_human_reviewed_state_and_comment(result_id: int) -> dict:
    """Gets the human-reviewed result from the database. It includes the state and the comment of the analysis if it has been verified that the result is a FALSE_POSITIVE or NOT_EXPLOITABLE result. Feel free to comment if you agree with the result (please justify). If the result is not found, return None. If the state is not defined, the results was not analyzed yet."""
    logger.info(f"Request for getting human-reviewed state and comment for result {result_id}...")
    try:
        # check if the result_id exists
        query = "SELECT count(result_id) FROM results where result_id = ?"
        (count, ) = cursor.execute(query, (result_id,)).fetchone()
        if count == 0:
            logger.error(f"Result ID {result_id} not found.")
            return None

        # get the human-reviewed state and comment
        query = "SELECT state, comment FROM results where result_id = ?"
        (state, comment) = cursor.execute(query, (result_id,)).fetchone()
        logger.info(
            f"Result ID {result_id} state: {state}, comment: {comment}")
        return {
            "state": state,
            "comment": comment
        }
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    return None


@mcp.tool(name="get_workspace_context", description="Get a summary of the workspace, including files and directories under the source folder.")
def get_workspace_context() -> dict:
    """Return a summary of the workspace (file and directory names) under the source folder."""
    logger.info("Request for getting workspace context...")
    import os
    context = []
    root_dir = os.path.join(INPUT_FILES_FOLDER, source_folder)
    for dirpath, dirnames, filenames in os.walk(root_dir):
        rel_dir = os.path.relpath(dirpath, root_dir)
        context.append({
            "directory": rel_dir,
            "files": filenames,
            "subdirs": dirnames
        })
    return context


def main():
    parser = argparse.ArgumentParser(description="MCP server python script")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="sse", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: sse")
    parser.add_argument("--database", type=str, default=DEFAULT_DB,
                        help="The name of sqlite3 database to be read.")
    parser.add_argument("--source-folder", type=str, default=INPUT_FILES_FOLDER,
                        help="The folder of the projects source-code in the input folder.")
    args = parser.parse_args()

    # initialize database
    try:
        global conn, cursor, source_folder
        conn = sqlite3.connect(args.database)
        cursor = conn.cursor()
        source_folder = args.source_folder
        logger.info(f"Connected to database: {args.database}")
    except Exception as e:
        logger.info(f"An error occurred when setting up the database: {e}")
        sys.exit(1)

    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(
                f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
            conn.close()
            sys.exit(1)
    else:
        logger.info("Starting server in stdio mode")
        try: 
            mcp.run()
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            conn.close()
            sys.exit(1)


if __name__ == "__main__":
    main()
