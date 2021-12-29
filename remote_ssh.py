import contextlib
import paramiko
import os
import time
import errno

_ONE_MINUTE = 60
_1_SECOND = 1
_10_SECONDS = 10.0
_20_SECONDS = 20.0
_BUFFER_SIZE = 4092
verbose = False

class paramikoServer:
    """ For SSH operations on hypervisor
    """
    def __init__(self, hostname=None, username=None, password=None, private_key_file=None, connect_timeout=None):
        self._hostname = hostname
        self._username = username
        self._password = password
        self._remotessh = None
        self._transport = None
        self._channel = None
        self._has_error = False
        self._remote_home_dir = None
        self._remote_ssh_dir = None
        self._linuxhostname = None
        self._sftp = None
		
        if os.path.exists(str(private_key_file)):
            self._private_key_file = private_key_file
        else:
            self._private_key_file = None
			
        if (self._password is None) and (self._private_key_file is None):
            """Try to guess the private key in user environment """
            if os.path.exists(os.path.expanduser('~/.ssh/id_rsa')):
                self._private_key_file = os.path.expanduser('~/.ssh/id_rsa')
            elif os.path.exists(os.path.expanduser('~/.ssh/id_dsa')):
                self._private_key_file = os.path.expanduser('~/.ssh/id_dsa')
            else:
                print(self._hostname + ": Missing password or key.\n")
        
        if self._password is not None:
            self._allow_agent = False
            self._look_for_keys = False
        else:
            self._allow_agent = True
            self._look_for_keys = True
        
        self._closed = False
        self._connect_timeout = connect_timeout if not None else _10_SECONDS

    def connectSsh(self):
        try:
            remotessh = paramiko.SSHClient()
            remotessh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            remotessh.connect(
                hostname=self._hostname,
                username=self._username,
                password=self._password,
                key_filename=self._private_key_file,
                allow_agent = self._allow_agent,
                look_for_keys = self._look_for_keys,
                timeout=self._connect_timeout,
                )
            self._remotessh = remotessh
        #except socket.error:
        #    print(self._hostname + ": SSH failed with socket error.\n")
        except paramiko.BadHostKeyException:
            print(self._hostname + ": SSH failed with server's host key unable get verified.\n")
        except paramiko.AuthenticationException:
            print(self._hostname + ": SSH failed with authentication exception event.\n")
        except paramiko.SSHException:
            print(self._hostname + ": SSH failed with some exception error.\n")
        finally:
            print(self._hostname + " connected sucessfully.\n")
			
        return self._remotessh

    def sendFile(self, localPath, remotePath):
        try:
            self._sftp = self._remotessh.open_sftp()
            self._sftp.put(localPath, remotePath)
            self._sftp.close()
            return True
        except Exception as e:
            self._sftp.close()
            self._has_error = True
            print("Error in sending {} to {}. {}.\n".format(localPath,remotePath, e))
            return False

    def downloadFile(self, remotePath, localPath):
        try:
            self._sftp = self._remotessh.open_sftp()
            self._sftp.get(remotePath, localPath)
            self._sftp.close()
            return True
        except Exception as e:
            self._sftp.close()
            self._has_error = True
            print("Error in downloading {} to {}. {}.\n".format(remotePath, localPath, e))
            return False

    def isFileExists(self, remotepath):
        try:
            self._sftp = self._remotessh.open_sftp()
            self._sftp.stat(remotepath)
        except Exception as e:
            if e.errno == errno.ENOENT:
                return False
        self._sftp.close()
        return True
 
    def listFiles(self, remotePath):
        fileList = {}
        try:
            self._sftp = self._remotessh.open_sftp()
            fileList = (self._sftp.listdir(remotePath))
            self._sftp.close()
        except Exception as e:
            print("{}".format(e))
        return fileList

    def closeSSH(self):
        try:
            if self._remotessh is not None:
                self._remotessh.close()
            self._closed = True
		
        except Exception as e:
            print("{}".format(e))

    def runCommand(self,command,sudo=None):
        try:
            self._transport = self._remotessh.get_transport()

            feedpasswrd = False
            if sudo == False:
                pass
            else:
                if (self._username is None):
                    self._username = self._transport.get_username()
                if self._username != "root":
                    command = "sudo -S -p '' %s" % command
                    feedpasswrd = self._password is not None and len(self._password) > 0

            #print command
            if self._transport is not None:
                new_session = self._transport.open_session()
                new_session.get_pty()
                stdin,stdout,stderr=self._remotessh.exec_command(command)
                if feedpasswrd:
                    stdin.write(self._password + "\n")
                    stdin.flush()

                error_list=stderr.readlines()
                new_session.close()
            
                if not len(error_list) == 0:
                    ##print(error_list)
                    self._has_error = True
                    return (error_list)
                else:
                    output=stdout.readlines()
                    return (output)
            else:
                raise paramiko.SSHException
                
        except Exception as e:
            print("{}".format(e))

"""
if __name__=="__main__":
    sut_IP = "10.239.46.23"
    sut_user = "root"
    sut_password = "password"
    command = "sudo sh /home/Set_BMC_User.sh"
    try:
        sutserver = paramikoServer(sut_IP, sut_user, sut_password)
        print("Establish ssh seesion to {}.\n".format(sut_IP))
        sutserver.connectSsh()
        if not sutserver.isFileExists("/home/Set_BMC_User.sh"):
            print("script doesn't exist on SUT, upload from host")
            sutserver.sendFile("C:/Users/weipengd/OneDrive - Intel Corporation/Desktop/intel doc/workspace/新建文件夹/redfish_debug/Set_BMC_User.sh","/home/Set_BMC_User.sh")
        print("Run command: {}.\n".format(command))
        stdout = sutserver.runCommand(command)
    except:
        print("Error inside ssh and execute")
    finally:
        sutserver.closeSSH()
    print(stdout[-1])
    print("execution finished")

"""