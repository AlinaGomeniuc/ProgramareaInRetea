# Programarea in Retea
## Laboratory work nr.1
The main task is to traverse links obtained from a docker server in order to save all the data from there. Once done, all the data should be converted to the same format. After that, it is required to create a multiple client server such that, all the clients will be able to request information from the server and get an response. The information that is stored on the local server is the one collected from the docker server.

### 1. Traverse the links
For the first part, we should access the root route. In order to traverse all the links present on the server, we should register using an Access-Token. It can be obtained from the ***/register*** link. So, we should make a get request on the link and save the data that is under the ***access_token*** key.
```python
response_register = requests.get(url + '/register')
access_token_register = response_register.json()["access_token"]
header_token = {'X-Access-Token': access_token_register}
```
Now, in ***header_token*** is the value of ***access_token*** key.

In order to traverse the links we should use recursive functions. Also, taking into account that the ***access_token*** has a timeout, we should use threads.
For this are required 2 functions: one for making the request and another for saving all the data.
**return_request_info**
```python
def return_request_info(link, header):
    response = requests.get(url + link, headers=header)
    traverse_link(response.json(), header)
```    
It is responsible for making the request and calling the main function responsible for the data traversing.

**traverse_link**
```python
def traverse_link(response_json, header):
    if 'msg' not in response_json:
        lock.acquire()
        all_info.append(parse_info(response_json))
        lock.release()
    if 'link' in response_json:
        links = response_json["link"]
        threads = list()
        for key, value in links.items():
            thread = threading.Thread(target=return_request_info, args=(value, header))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
```
It is receiving a json and the access token as parameters. If the json has a key ***link***, all the values of the link are saved in an array. Iterating through the links, we are creating a new thread for each link, which has the target to the previous function responsible for making the get requests. In this way we are appending all the data from the links to an array. In order to ensure that all the threads will be executed, we are appending them to a list of **threads** and after that are joining each thread. 

**parse_info**
```python
def parse_info(info):
    data = info["data"]
    if 'mime_type' in info:
        if info["mime_type"] == "application/xml":
            return convert_xml(data)
        elif info["mime_type"] == "application/x-yaml":
            return convert_yaml(data)
        elif info["mime_type"] == "text/csv":
            return convert_csv(data)
    else:
        return convert_json(data)
```
This function is responsible for calling the necessary converting function depending on the ***mime_type***. On the server are 4 types of data format: csv, yaml, xml and json.
### 2. Convert the information to the same format type
```python
def convert_yaml(data):
    a = json.dumps(yaml.safe_load(data))
    return json.loads(a)


def convert_csv(data):
    json_csv = []
    string_file = StringIO(data)
    csv_reader = csv.DictReader(string_file)

    for row in csv_reader:
        json_csv.append(row)
    return json_csv


def convert_xml(data):
    parse = xmltodict.parse(data)
    json_string = json.dumps(parse)
    json_parse = json.loads(json_string)
    xml_info = json_parse['dataset']['record']
    return xml_info


def convert_json(data):
    data = str(data).replace(',]', ']')
    return json.loads(data)
```
All functions are responsible for converting its data format to a python dictionary.

### 3. Server part
Sockets and the socket API are used to send messages across a network. We ll create a socket object using socket.socket() and specify the socket type as socket.SOCK_STREAM. By this, we will get the default protocol that is TCP.
```python
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
```
In order to manage a client-server connection a host and port is required. Having them we are able to associate the socket with a specific network interface and port number using the .bind() function.
```python
    try:
        s.bind((HOST, PORT))
    except:
        print("Bind failed")
        sys.exit()
```
In order to enable a server to accept connections, the .listen() function should be used. It specifies the number of unaccepted connections that the system will allow before refusing new connections. 
```python
s.listen(10)
```
The accept()function blocks and waits for an incoming connection. When a client connects, it returns a new socket object representing the connection and a tuple holding the address of the client. 
In order to be able to accept connection all the time, a while loop is used on the server part. Also, in order to ensure that each client will be able to make requests to the server all the time, we use threads. For closing the socket, the close() function is used.
```python
    try:
        while 1:
            conn, addr = s.accept()
            print("Connected with " + addr[0] + ":" + str(addr[1]))
            thread = threading.Thread(target=client_thread, args=(conn,))
            thread.start()
    finally:
        s.close()
 ``` 
For the client part we should be able to receive data from server and to send it back. 
For receiving is used .recv() function, having as parameter the amount of bytes that should be accepted. Once the command's keyword is present in the user's input(**get**) the splitting function is used. In this manner we are getting all the arguments of the command. Then, the obtained array is sent as parameter to the function with the main logic of getting the data from the server. The response is held in a variable. After that it is converted to a string and sent to the server using **sendall()** function.
In case a wrong command is written, it notifies the client about that.
All the requests are always processed by the server, because a while loop is used for each thread.
In case the user writes **quit**, the connection is closed.
**client_thread**
```python
def client_thread(connection):
    connection.send("Welcome to the server. Type the needed command (syntax: get _ )\n".encode())
    while True:
        data = connection.recv(1024)
        string_data = str(data)
        if 'get ' in string_data:
            string_data = string_data.split(' ')
            response = send_client(string_data)
            reply = ''.join(str(response))
            response.clear()
        else:
            if 'quit' in string_data:
                break
            else:
                reply = "Wrong syntax. Try again"

        connection.sendall(reply.encode())
        connection.send('\n'.encode())
    connection.close()
```
**send_client**
Here, we are deleting the \r\n from the received data. The resulting array is traversed for headers and conditions.
```python
def send_client(arguments):
    headers = []
    tuples = []
    condition = []
    arguments[0] = arguments[0].replace("b'", "")
    last = arguments[len(arguments) - 1].replace("\\r\\n", '')
    arguments[len(arguments) - 1] = last.replace("\'", '')
    for field in arguments:
        if field not in ['get', 'where']:
            headers.append(field)
        if field == 'where':
            condition = arguments[len(arguments) - 1]
            break
```
Once found, a pretty table is constructed using the headers.
Now each node is traversed through subnodes. If a header is found out in the subnote, its value is appended to the tuple that later will be sent to the table, otherwise the **null** value will the appended to the tuple. In case the client's command contains ***where***, the next elements are saved in a variable - **condition**. So, a **validate_condition** function will the called, having as one parameters the condition.
After all the operations, the **tuple** array is cleared.
```python
    final = PrettyTable(headers)

    for node in all_info:
        for subnode in node:
            for field in headers:
                if field in subnode:
                    if condition in arguments:
                        validate_condition(condition, subnode[field], tuples)
                    else:
                        tuples.append(subnode[field])
                elif field not in subnode and condition not in arguments:
                    tuples.append("null")
            if tuples:
                final.add_row(tuples)
                tuples.clear()
    return final
```    
**validate_condition**
It is based on finding the **%** symbol, or any relational operations. 
In case of **%** we have 2 cases, when we have 1 **%** and when we have 2 **%**. 
When we use just 1, we are searching for cases when it starts, ends or is between a string. If there is some data that accomplishes this requirement, this data is appendend to the tuple.
```python
def validate_condition(condition, field, tuples):
    if '%' in condition:
        counter = condition.count('%')
        if counter == 1:
            if '%' == condition[0]:
                pattern = condition[1:len(condition)]
                if field.startswith(pattern):
                    tuples.append(field)
            elif '%' == condition[len(condition) - 1]:
                pattern = condition[0:len(condition) - 1]
                if field.endswith(pattern):
                    tuples.append(field)
            else:
                pattern = condition.split('%')
                if field.startswith(pattern[0]) and field.endswith(pattern[1]):
                    tuples.append(field)
        if counter == 2:
            pattern = condition.split('%')
            if pattern[1] in field:
                tuples.append(field)
```                
In the same manner the validation on relational operations works. It splits the condition based on the sign, and compares the value of elements.
```python
    else:
        operation = ['<=', '>=', '<', '>', '=']
        for sign in operation:
            if sign in condition:
                command = condition.split(sign)
                if command[1].isdigit():
                    if sign == '<':
                        if int(field) < int(command[1]):
                            tuples.append(field)
                            break
                    if sign == '>':
                        if int(field) > int(command[1]):
                            tuples.append(field)
                            break
                    if sign == '=':
                        if int(field) == int(command[1]):
                            tuples.append(field)
                            break
                    if sign == '>=':
                        if int(field) >= int(command[1]):
                            tuples.append(field)
                            break
                    if sign == '<=':
                        if int(field) <= int(command[1]):
                            tuples.append(field)
                            break
 ```                           
