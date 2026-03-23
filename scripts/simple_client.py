import requests
from typing import Iterator, Optional, Tuple
import json
import os
import sys

# Configuration
SERVER_URL = "http://www.crimmy.top:14001"
LAB1_URI = "/test/lab1"
LAB2_URI = "/test/lab2"
LAB3_URI = "/test/lab3"
MONITOR_URI_PRIFFIX = "/monitor"
CHUNK_SIZE = 8192  # 8KB

def upload_file_with_streaming_response(
    url: str,
    file_path: str,
    chunk_size: int = 8192,
    timeout: float = 30.0,
) -> Iterator[bytes]:
    '''
    Uploads a file to the specified URL using streaming and 
    yields the server's streaming response.

    :param url: The URL to upload the file to.
    :type url: str
    :param file_path: The path to the file to be uploaded.
    :type file_path: str
    :param chunk_size: The size of each chunk to read from the file.
    :type chunk_size: int
    :param timeout: The timeout for the request in seconds.
    :type timeout: float
    :return: An iterator yielding chunks of the server's response.
    :rtype: Iterator[bytes]
    '''
    def file_generator():
        if file_path == "-":
            while True:
                chunk = sys.stdin.buffer.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        else:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
    
    try:
        with requests.post(
            url,
            data=file_generator(),
            stream=True,
            timeout=timeout
        ) as response:
            response.raise_for_status()
            
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    yield chunk
                    
    except requests.exceptions.RequestException as e:
        raise Exception(f"{e}")

def lab_task(
    lab_uri: str,
    file_path: str,
    chunk_size: int = 8192,
    timeout: float = 30.0,
) -> Optional[str]:
    '''
    Send a lab task reqeust to the server and handle the streaming response.
    
    :param lab_uri: The corresponding lab URI (e.g., `/test/lab1`)
    :type lab_uri: str
    :param file_path: The path to the compressed source file (e.g., `.tar.gz`)
    :type file_path: str
    :param chunk_size: The size of each chunk to send from the file
    :type chunk_size: int
    :param timeout: The timeout for the request in seconds
    :type timeout: float
    :return: The UUID returned by the server upon successful processing
    :rtype: str | None
    '''
    url = SERVER_URL + lab_uri
    try:
        total_size = os.path.getsize(file_path) if file_path != "-" else 0
        uploaded_size = 0
        uuid = ""
        buf = ""
        for response_chunk in \
            upload_file_with_streaming_response(
            url, 
            file_path, 
            chunk_size=chunk_size, timeout=timeout):

            buf += response_chunk.decode('utf-8')
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                json_data = json.loads(line)
                if json_data["status"] == "Processing":
                    uploaded_size += json_data["progress"]
                    print(f"\rUploaded {uploaded_size}/{total_size} bytes", end='', flush=True)
                elif json_data["status"] == "FileUploadCompleted":
                    print("\nFile upload and processing completed.")
                elif json_data["status"] == "TooManyRequests":
                    raise Exception("Server is busy. Too many requests.")
                elif json_data["status"] == "OK":
                    uuid = json_data["uuid"]
                    print(f"Server response OK with UUID: {json_data['uuid']}")
                else:
                    raise Exception(f"Unexpected response: {json_data}")
        # handle any remaining data in buffer (no trailing newline)
        if buf.strip():
            json_data = json.loads(buf.strip())
            if json_data["status"] == "OK":
                uuid = json_data["uuid"]
                print(f"Server response OK with UUID: {json_data['uuid']}")
        return uuid
    except Exception as e:
        raise Exception(f"Error during lab task: {e}")
    
def monitor_task(
    uuid: str,
    timeout: float = 1800.0,
):
    '''
    Send a monitor task request to the server to check the status of a lab task.
    
    :param uuid: The UUID provided by the server for the lab task
    :type uuid: str
    :param chunk_size: The size of each chunk to read from the response
    :type chunk_size: int
    :param timeout: The timeout for the request in seconds. Recommended to be longer than 1800s,
    because this is the default timeout for a lab task.
    :type timeout: float
    '''
    url = SERVER_URL + MONITOR_URI_PRIFFIX + f"/{uuid}"
    def monitor_reqeust_generator():
        try:
            with requests.get(url, timeout=timeout, stream=True) as response:
                response.raise_for_status()

                for chunk in response.iter_content(chunk_size=None):
                    if chunk:
                        yield chunk
        except requests.exceptions.RequestException as e:
            print(f"\n\033[0;31m[TEST FAILED]\033[0m {e}")
            return
    try:
        buf = ""
        for chunk in monitor_reqeust_generator():
            buf += chunk.decode('utf-8')
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                json_data = json.loads(line)
                if json_data["status"] == "QUEUE":
                    position = json_data["position"]
                    print(f"\rTask is in queue. Position: {position}", end='', flush=True)
                elif json_data["status"] == "PROCESSING":
                    output = json_data["progress"]["output"]
                    print(f"{output}", flush=True)
                elif json_data["status"] == "COMPLETED":
                    result_code = json_data["result"]["result_code"]
                    time = json_data["result"]["time_ms"] / 1000.0
                    if result_code == "Completed":
                        print(f"\033[0;32m[TEST COMPLETED]\033[0m Time elapsed: {time}s")
                    else:
                        print(f"\033[0;31m[TEST FAILED]\033[0m Result code: {result_code}. Time elapsed: {time}s")
                else:
                    print(f"Oops! Something went wrong: test id not found.")
    except Exception as e:
        print(f"\n\033[0;31m[TEST FAILED]\033[0m {e}")
        return

def arg_transfer(arg1: str, arg2: str) -> Tuple[str, str]:
    '''
    Validates and transfers command-line arguments.
    
    :param arg1: the first command-line argument
    :type arg1: str
    :param arg2: the second command-line argument
    :type arg2: str
    :return: (validated lab URI, validated file path)
    :rtype: Tuple[str, str]
    '''
    valid_labs = {
        "lab1": LAB1_URI,
        "lab2": LAB2_URI,
        "lab3": LAB3_URI
    }
    if arg1.lower() not in valid_labs:
        print("Invalid lab specified. Choose from lab1, lab2, or lab3.")
        sys.exit(1)
    arg1 = valid_labs[arg1]

    if (not os.path.exists(arg2) or not os.path.isfile(arg2)) and arg2 != "-":
        print(f"File {arg2} does not exist or is not a file.")
        sys.exit(1)
    return (arg1, arg2)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python simple_client.py <lab1 | lab2 | lab3> <lab_src_file>")
        print("Example: python simple_client.py lab1 ./testfile.tar.gz")
        print("If file path is \"-\", the client will read from standard input.")
        sys.exit(1)
    lab_uri, file_path = arg_transfer(sys.argv[1], sys.argv[2]) 

    try:
        print("=" * 35 + "UPLOADING" + "=" * 35)
        uuid = lab_task(lab_uri, file_path, CHUNK_SIZE)
        print("Test begin.")
        if uuid is None or uuid == "":
            raise Exception("\n\033[0;31m[UPLOAD FAILED]\033[0m Failed to obtain UUID from server response.")

        print("=" * 37 + "RESULT" + "=" * 37)
        monitor_task(uuid)
    except Exception as e:
        print(f"\n\033[0;31m[FAILED]\033[0m {e}")