import os
import paramiko
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import ConnectSerializer, InitiateSerializer, FilterSerializer, TesterSerializer
from .models import ConnectionLog, ProcessCapture, ProcessFilteredResult
import time
import uuid
from django.conf import settings
import csv
from rest_framework.parsers import JSONParser
import shutil
from rest_framework.permissions import IsAuthenticated

class ConnectAPIView(APIView):
    permission_classes = [IsAuthenticated]      # No permission checks

    def post(self, request):
        serializer = ConnectSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        username = data['username']
        password = data['password']
        ip_address = data['ip_address']
        connection_name = data['connection_name']

        # Check if connection_name already exists
        if ConnectionLog.objects.filter(connection_name=connection_name).exists():
            return Response(
                {"error": f"Connection name '{connection_name}' already exists. Please use a unique name."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # SSH Connect to remote Windows machine
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip_address, username=username, password=password)

            # Use CMD instead of PowerShell - more reliable over SSH
            # Method 1: Using DIR command (most reliable)
            cmd_commands = [
                'dir "C:\\Program Files\\*.exe" /S /B 2>nul',
                'dir "C:\\Program Files (x86)\\*.exe" /S /B 2>nul',
                'dir "C:\\Windows\\System32\\*.exe" /B 2>nul'
            ]
            
            all_exe_files = []
            debug_info = {'commands_executed': []}
            
            for cmd in cmd_commands:
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
                    output = stdout.read().decode('utf-8', errors='replace')
                    error = stderr.read().decode('utf-8', errors='replace')
                    
                    debug_info['commands_executed'].append({
                        'command': cmd,
                        'output_lines': len(output.splitlines()) if output else 0,
                        'has_error': bool(error)
                    })
                    
                    # Process output - each line is a full path to an .exe file
                    if output:
                        for line in output.splitlines():
                            line = line.strip()
                            if line and line.endswith('.exe'):
                                try:
                                    fullpath = line
                                    name = os.path.basename(fullpath)
                                    directory = os.path.dirname(fullpath)
                                    
                                    all_exe_files.append({
                                        "name": name,
                                        "directory": directory,
                                        "fullname": fullpath
                                    })
                                except Exception:
                                    continue
                                    
                except Exception as e:
                    debug_info['commands_executed'].append({
                        'command': cmd,
                        'error': str(e)
                    })
                    continue

            # Alternative Method 2: Using WMIC (if DIR doesn't work)
            if not all_exe_files:
                wmic_cmd = 'wmic process get ExecutablePath /format:csv 2>nul | findstr ".exe"'
                try:
                    stdin, stdout, stderr = ssh.exec_command(wmic_cmd, timeout=40)
                    wmic_output = stdout.read().decode('utf-8', errors='replace')
                    
                    if wmic_output:
                        debug_info['wmic_attempted'] = True
                        debug_info['wmic_output_length'] = len(wmic_output)
                        
                        # Parse WMIC output (CSV format)
                        for line in wmic_output.splitlines():
                            if '.exe' in line and ',' in line:
                                try:
                                    # WMIC CSV format: Node,ExecutablePath
                                    parts = line.split(',', 1)
                                    if len(parts) > 1:
                                        exe_path = parts[1].strip().strip('"')
                                        if exe_path and exe_path.endswith('.exe'):
                                            name = os.path.basename(exe_path)
                                            directory = os.path.dirname(exe_path)
                                            
                                            # Avoid duplicates
                                            if not any(app['fullname'] == exe_path for app in all_exe_files):
                                                all_exe_files.append({
                                                    "name": name,
                                                    "directory": directory,
                                                    "fullname": exe_path
                                                })
                                except Exception:
                                    continue
                except Exception as e:
                    debug_info['wmic_error'] = str(e)

            # Alternative Method 3: Simple PowerShell with different approach
            if not all_exe_files:
                # Try a simpler PowerShell command that might work better over SSH
                simple_ps_cmd = 'powershell "ls \'C:\\Program Files\\*.exe\' -r -name | select -f 10"'
                try:
                    stdin, stdout, stderr = ssh.exec_command(simple_ps_cmd, timeout=40)
                    ps_output = stdout.read().decode('utf-8', errors='replace')
                    
                    if ps_output:
                        debug_info['simple_ps_attempted'] = True
                        debug_info['simple_ps_output'] = ps_output[:200]
                        
                        # This returns just filenames, so we need to construct full paths
                        base_path = "C:\\Program Files"
                        for line in ps_output.splitlines():
                            filename = line.strip()
                            if filename.endswith('.exe'):
                                all_exe_files.append({
                                    "name": filename,
                                    "directory": base_path,
                                    "fullname": os.path.join(base_path, filename).replace('/', '\\')
                                })
                except Exception as e:
                    debug_info['simple_ps_error'] = str(e)

            # Remove duplicates based on fullname
            seen_paths = set()
            unique_apps = []
            for app in all_exe_files:
                if app['fullname'] not in seen_paths:
                    seen_paths.add(app['fullname'])
                    unique_apps.append(app)

            # Save connection log entry to DB
            ConnectionLog.objects.create(
                username=username,
                password=password,
                ip_address=ip_address,
                connection_name=connection_name
            )

            # Close SSH connection
            ssh.close()

            # Return the results
            return Response({
                "message": "Connection established successfully",
                "connection_name": connection_name,
                "apps": unique_apps,
                "total_apps": len(unique_apps),
                "debug": debug_info
            }, status=status.HTTP_200_OK)

        except paramiko.AuthenticationException:
            return Response({"error": "Authentication failed"}, status=status.HTTP_401_UNAUTHORIZED)
        except paramiko.SSHException as e:
            return Response({"error": f"SSH connection failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# Path to Procmon64.exe in your local project folder
PROC_MON_LOCAL_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'Procmon64.exe')

class InitiateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = InitiateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        exe_name = data['name']
        exe_directory = data['directory']
        exe_fullname = data['fullname']
        connection_name = data['connection_name']

        try:
            # Get connection details from ConnectionLog
            try:
                connection_log = ConnectionLog.objects.get(connection_name=connection_name)
            except ConnectionLog.DoesNotExist:
                return Response(
                    {"error": f"Connection '{connection_name}' not found. Please establish connection first."}, 
                    status=status.HTTP_404_NOT_FOUND
                )

            # Extract credentials from the connection log
            username = connection_log.username
            password = connection_log.password
            ip_address = connection_log.ip_address

            # Create ProcessCapture record to store input
            process_capture = ProcessCapture.objects.create(
                connection=connection_log,
                exe_name=exe_name,
                exe_directory=exe_directory,
                exe_fullname=exe_fullname,
                success=False  # Will update this based on success
            )

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip_address, username=username, password=password)

            # Create temp directory
            session_id = str(uuid.uuid4())[:8]
            temp_dir = f"C:\\temp_proc_{session_id}"
            ssh.exec_command(f'mkdir "{temp_dir}" 2>nul')
            time.sleep(1)

            # Transfer Procmon64.exe
            sftp = ssh.open_sftp()
            remote_procmon = f"{temp_dir}\\Procmon64.exe"
            sftp.put(PROC_MON_LOCAL_PATH, remote_procmon)

            # Batch content with corrected quoting and logic
            batch_content = f'''@echo off
    cd /D "{temp_dir}"

    echo Cleaning up existing processes...
    taskkill /F /IM Procmon64.exe 2>nul
    taskkill /F /IM "{exe_name}" 2>nul
    timeout /T 3 /NOBREAK >nul

    set BACKING_FILE={temp_dir}\\capture.pml
    set CSV_FILE={temp_dir}\\procmon_output.csv
    set EXE_NAME={exe_name}
    set EXE_FULL_PATH={exe_directory}\\{exe_name}

    echo Starting Procmon...
    start /B "" Procmon64.exe /AcceptEula /Quiet /Minimized /BackingFile "%BACKING_FILE%"

    timeout /T 3 /NOBREAK >nul

    echo Launching target executable...
    start "" "%EXE_FULL_PATH%"

    timeout /T 3 /NOBREAK >nul

    echo Checking if processes are running...
    tasklist | findstr /I "Procmon64.exe" >nul
    if %errorlevel% neq 0 (
        echo ERROR: Procmon is not running
        goto cleanup
    )
    tasklist | findstr /I "%EXE_NAME%" >nul
    if %errorlevel% neq 0 (
        echo WARNING: Target application may not be running
    ) else (
        echo Both processes are running
    )

    echo Waiting 40 seconds for monitoring...
    timeout /T 40 /NOBREAK >nul

    echo Closing target executable...
    taskkill /F /IM "%EXE_NAME%" 2>nul
    timeout /T 2 /NOBREAK >nul

    echo Stopping Procmon...
    Procmon64.exe /Terminate
    timeout /T 5 /NOBREAK >nul

    echo Verifying Procmon has stopped...
    :checkstop
    tasklist | findstr /I "Procmon64.exe" >nul
    if %errorlevel% equ 0 (
        timeout /T 2 /NOBREAK >nul
        goto checkstop
    )

    echo Procmon stopped.

    if exist "%BACKING_FILE%" (
        for %%F in ("%BACKING_FILE%") do (
            if %%~zF gtr 0 (
                echo PML file created: %%~zF bytes
            ) else (
                echo ERROR: Capture file is empty
                goto cleanup
            )
        )
    ) else (
        echo ERROR: Capture file not found
        goto cleanup
    )

    timeout /T 3 /NOBREAK >nul

    echo Converting PML to CSV...
    Procmon64.exe /AcceptEula /OpenLog "%BACKING_FILE%" /SaveAs "%CSV_FILE%"
    timeout /T 10 /NOBREAK >nul

    if exist "%CSV_FILE%" (
        for %%F in ("%CSV_FILE%") do (
            echo CSV created: %%~zF bytes
        )
    ) else (
        echo ERROR: CSV file was not created
    )

    :cleanup
    echo Monitoring complete.
    '''

            # Upload batch file
            batch_file = f"{temp_dir}\\monitor_process.bat"
            with sftp.open(batch_file, 'w') as f:
                f.write(batch_content)
            sftp.close()

            # Execute the batch file
            stdin, stdout, stderr = ssh.exec_command(f'cmd /c ""{batch_file}""', timeout=180)
            batch_output = stdout.read().decode('utf-8', errors='replace')
            batch_error = stderr.read().decode('utf-8', errors='replace')

            time.sleep(5)

            # Read CSV
            csv_content = ""
            csv_file = f"{temp_dir}\\procmon_output.csv"
            try:
                sftp = ssh.open_sftp()
                try:
                    sftp.stat(csv_file)
                except:
                    raise Exception("CSV output file not created")

                with sftp.open(csv_file, 'r') as remote_file:
                    csv_content = remote_file.read().decode('utf-8', errors='replace')
                sftp.close()
            except Exception as e:
                csv_content = ""

            # Optional cleanup
            ssh.exec_command(f'rmdir /S /Q "{temp_dir}" 2>nul')
            ssh.close()

            # Generate a unique filename
            unique_filename = f"procmon_output_{uuid.uuid4().hex[:8]}.csv"
            save_path = os.path.join(settings.MEDIA_ROOT, 'csv', unique_filename)

            # Ensure directory exists
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            # Save CSV to disk
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(csv_content)

            # Update ProcessCapture record with output
            file_path = f"{settings.MEDIA_URL}csv/{unique_filename}"
            process_capture.filename = unique_filename
            process_capture.file_path = file_path
            process_capture.success = True
            process_capture.save()

            # Return response with path or info
            return Response({
                "message": "Process monitoring completed successfully",
                "connection_name": connection_name,
                "process_capture_id": process_capture.id,
                "input": {
                    "exe_name": exe_name,
                    "exe_directory": exe_directory,
                    "exe_fullname": exe_fullname
                },
                "output": {
                    "filename": unique_filename,
                    "file_path": file_path,
                    "csv_size": len(csv_content)
                }
            }, status=status.HTTP_200_OK)

        except ConnectionLog.DoesNotExist:
            process_capture.error_message = "Connection not found"
            process_capture.save()
            return Response(
                {"error": f"Connection '{connection_name}' not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            # Update ProcessCapture record with error
            if 'process_capture' in locals():
                process_capture.error_message = str(e)
                process_capture.save()
            
            return Response({
                "error": str(e),
                "details": "Failed to monitor process with Procmon",
                "connection_name": connection_name
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class FilterProcessAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = FilterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        connection_name = serializer.validated_data['connection_name']

        try:
            # Get connection log
            try:
                connection_log = ConnectionLog.objects.get(connection_name=connection_name)
            except ConnectionLog.DoesNotExist:
                return Response(
                    {"error": f"Connection '{connection_name}' not found."}, 
                    status=status.HTTP_404_NOT_FOUND
                )

            # Clear existing filtered results for this connection to avoid duplicates
            ProcessFilteredResult.objects.filter(connection=connection_log).delete()

            # Get all successful ProcessCapture records for this connection
            process_captures = ProcessCapture.objects.filter(
                connection=connection_log, 
                success=True
            ).exclude(filename__isnull=True).exclude(filename__exact='')

            if not process_captures.exists():
                return Response(
                    {"error": f"No successful process captures found for connection '{connection_name}'."}, 
                    status=status.HTTP_404_NOT_FOUND
                )

            all_filtered_results = []
            total_matches = 0

            for process_capture in process_captures:
                csv_filename = process_capture.filename
                application_name = process_capture.exe_name
                csv_path = os.path.join(settings.MEDIA_ROOT, 'csv', csv_filename)

                if not os.path.exists(csv_path):
                    continue

                # Apply filters to CSV
                matches = []
                try:
                    with open(csv_path, newline='', encoding='utf-8') as csvfile:
                        reader = csv.DictReader(csvfile)
                        for row in reader:
                            # Apply filters:
                            # 1. Process name is <application_name.exe>
                            # 2. Path ends with .dll
                            # 3. Result contains "not found"
                            if (row.get("Process Name") == application_name and
                                row.get("Path", "").lower().endswith(".dll") and
                                "not found" in row.get("Result", "").lower()):
                                
                                # Save to ProcessFilteredResult table
                                filtered_result = ProcessFilteredResult.objects.create(
                                    connection=connection_log,
                                    process_capture=process_capture,
                                    csv_filename=csv_filename,
                                    application_name=application_name,
                                    process_name=row["Process Name"],
                                    path=row["Path"],
                                    result=row["Result"]
                                )

                                match_data = {
                                    "id": filtered_result.id,
                                    "process_name": row["Process Name"],
                                    "path": row["Path"],
                                    "result": row["Result"]
                                }
                                matches.append(match_data)

                except Exception as e:
                    continue

                if matches:
                    all_filtered_results.append({
                        "csv_filename": csv_filename,
                        "application_name": application_name,
                        "matches": matches,
                        "match_count": len(matches)
                    })
                    total_matches += len(matches)

            return Response({
                "message": "Filtering completed successfully",
                "connection_name": connection_name,
                "total_csv_files_processed": len(process_captures),
                "total_matches": total_matches,
                "filtered_results": all_filtered_results
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": str(e),
                "details": "Failed to filter process data"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Path to the DLL in the bin folder
DLL_LOCAL_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'test.dll')

class TesterAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TesterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        connection_name = serializer.validated_data['connection_name']
        id_string = serializer.validated_data['id']

        try:
            # Parse the ID string to get individual IDs
            id_list = [id_str.strip() for id_str in id_string.split(',') if id_str.strip()]
            
            if not id_list:
                return Response(
                    {"error": "No valid IDs provided"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get connection log
            try:
                connection_log = ConnectionLog.objects.get(connection_name=connection_name)
            except ConnectionLog.DoesNotExist:
                return Response(
                    {"error": f"Connection '{connection_name}' not found."}, 
                    status=status.HTTP_404_NOT_FOUND
                )

            # Get filtered results matching the connection and IDs
            filtered_results = ProcessFilteredResult.objects.filter(
                connection=connection_log,
                id__in=id_list
            )

            if not filtered_results.exists():
                return Response(
                    {"error": f"No filtered results found for the provided IDs in connection '{connection_name}'."}, 
                    status=status.HTTP_404_NOT_FOUND
                )

            # Check if DLL exists in bin folder
            if not os.path.exists(DLL_LOCAL_PATH):
                return Response(
                    {"error": "DLL file not found in bin folder"}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Extract SSH credentials
            username = connection_log.username
            password = connection_log.password
            ip_address = connection_log.ip_address

            # Establish SSH connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip_address, username=username, password=password)

            # Ensure /media/dlls/ directory exists
            dlls_dir = os.path.join(settings.MEDIA_ROOT, 'dlls')
            os.makedirs(dlls_dir, exist_ok=True)

            processed_results = []
            applications_to_start = set()

            for result in filtered_results:
                dll_path = result.path
                dll_name = os.path.basename(dll_path)
                dll_directory = os.path.dirname(dll_path)

                # Create renamed DLL in /media/dlls/
                local_dll_path = os.path.join(dlls_dir, dll_name)
                shutil.copy2(DLL_LOCAL_PATH, local_dll_path)

                try:
                    # Ensure remote directory exists
                    ssh.exec_command(f'mkdir "{dll_directory}" 2>nul')
                    time.sleep(1)

                    # Transfer DLL to remote machine
                    sftp = ssh.open_sftp()
                    sftp.put(local_dll_path, dll_path)
                    sftp.close()

                    # Get the application exe from the process capture
                    application_exe = result.process_capture.exe_fullname
                    applications_to_start.add(application_exe)

                    processed_results.append({
                        "id": result.id,
                        "dll_name": dll_name,
                        "dll_path": dll_path,
                        "local_dll_path": local_dll_path,
                        "application_exe": application_exe,
                        "status": "success"
                    })

                except Exception as e:
                    processed_results.append({
                        "id": result.id,
                        "dll_name": dll_name,
                        "dll_path": dll_path,
                        "error": str(e),
                        "status": "failed"
                    })

            # Start all unique applications using batch files for GUI execution
            started_applications = []
            session_id = str(uuid.uuid4())[:8]
            
            for app_exe in applications_to_start:
                try:
                    # Create a temporary directory for this session
                    temp_dir = f"C:\\temp_launch_{session_id}"
                    ssh.exec_command(f'mkdir "{temp_dir}" 2>nul')
                    time.sleep(1)

                    # Create batch file content to launch application graphically
                    batch_content = f'''@echo off
title Application Launcher - {os.path.basename(app_exe)}

echo Starting application: {app_exe}
echo.

REM Check if the executable exists
if not exist "{app_exe}" (
    echo ERROR: Application not found at {app_exe}
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

echo Launching application in GUI mode...
echo.

REM Start the application with GUI visibility
start "" "{app_exe}"

REM Wait a moment to see if application started
timeout /T 3 /NOBREAK >nul

REM Check if the process is running
tasklist | findstr /I "{os.path.basename(app_exe)}" >nul
if %errorlevel% equ 0 (
    echo SUCCESS: Application started successfully!
    echo Process is running: {os.path.basename(app_exe)}
) else (
    echo WARNING: Could not verify if application started
    echo This might be normal for some applications
)

echo.
echo Application launch attempt completed.
echo This window will close in 10 seconds...
timeout /T 10 /NOBREAK >nul

REM Cleanup
cd /D C:\\
rmdir /S /Q "{temp_dir}" 2>nul

exit /b 0
'''

                    # Upload batch file to remote machine
                    batch_filename = f"launch_{os.path.basename(app_exe).replace('.exe', '')}_{session_id}.bat"
                    batch_path = f"{temp_dir}\\{batch_filename}"
                    
                    sftp = ssh.open_sftp()
                    with sftp.open(batch_path, 'w') as batch_file:
                        batch_file.write(batch_content)
                    sftp.close()

                    # Execute the batch file in a new window (GUI mode)
                    # Using 'cmd /c start' to ensure it runs in a new window
                    launch_command = f'cmd /c start "App Launcher" /wait "{batch_path}"'
                    
                    # Execute the launch command
                    stdin, stdout, stderr = ssh.exec_command(launch_command, timeout=30)
                    
                    # Read output for debugging
                    launch_output = stdout.read().decode('utf-8', errors='replace')
                    launch_error = stderr.read().decode('utf-8', errors='replace')
                    
                    # Wait a moment for the application to start
                    time.sleep(2)
                    
                    # Verify if the process is running
                    stdin, stdout, stderr = ssh.exec_command(f'tasklist | findstr /I "{os.path.basename(app_exe)}"', timeout=10)
                    process_check = stdout.read().decode('utf-8', errors='replace')
                    
                    is_running = bool(process_check.strip())
                    
                    started_applications.append({
                        "application": app_exe,
                        "batch_file": batch_path,
                        "process_running": is_running,
                        "launch_output": launch_output[:200] if launch_output else "",
                        "status": "started_successfully" if is_running else "started_but_not_verified"
                    })

                except Exception as e:
                    started_applications.append({
                        "application": app_exe,
                        "error": str(e),
                        "status": "failed_to_start"
                    })

            # Close SSH connection
            ssh.close()

            return Response({
                "message": "Tester API completed successfully",
                "connection_name": connection_name,
                "processed_ids": id_list,
                "total_processed": len(processed_results),
                "successful_transfers": len([r for r in processed_results if r["status"] == "success"]),
                "failed_transfers": len([r for r in processed_results if r["status"] == "failed"]),
                "processed_results": processed_results,
                "started_applications": started_applications
            }, status=status.HTTP_200_OK)

        except paramiko.AuthenticationException:
            return Response({"error": "SSH Authentication failed"}, status=status.HTTP_401_UNAUTHORIZED)
        except paramiko.SSHException as e:
            return Response({"error": f"SSH connection failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({
                "error": str(e),
                "details": "Failed to process tester request"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)