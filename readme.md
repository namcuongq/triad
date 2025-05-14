# Triad

Triad is a command-line tool written in Go that launches a Windows `.exe` file as a process and prevents it from loading `.dll` files whose names contain a specific 3-character substring provided by the user. This can be useful for security analysis, dependency management, or preventing special libraries from being loaded.

## Features

- **DLL Filtering**: Prevents the process from loading `.dll` files that contain the user-specified 3-character substring (case-insensitive).
- **Command-Line Interface**: Uses flags (`--exe` and `--dll`) for easy integration into scripts or workflows.

## Installation

1. Ensure you have [Go](https://golang.org/doc/install) installed (version 1.16 or later recommended).
2. Clone the repository or download the source code:
   ```bash
   git clone <repository-url>
   cd triad
   ```
3. Build the tool:
   ```bash
   go build -o triad
   ```

## Usage

Run the tool with the following command:

```bash
./triad --exe <path_to_exe> --dll <3_char_substring>
```

### Flags

- `--exe`: Path to the `.exe` file to launch as a process (e.g., `C:\example\app.exe`).
- `--dll`: A 3-character substring to match against `.dll` file names to prevent loading (e.g., `DLP`).

### Example

To launch `app.exe` and prevent it from loading `.dll` files containing the substring `DLP`:

```bash
./triad --exe app.exe --dll DLP
```

**Sample Output**:
```
   _____ _          
  |_   _| |         
    | | | |__   ___ 
    | | | '_ \ / __|
   _| |_| | | | (__ 
  |_____|_| |_|____|
  
  Triad: DLL Unload Tool
  Filter DLLs with 3-character substring
  Version: v1.0.0

Process started with PID: 1234
Prevented loading of DLL containing: dlp
```

If no `.dll` files match the substring:
```
Process started with PID: 1234
No DLLs containing 'dlp' were attempted to be loaded.
```

If the `.exe` fails to start:
```
Error launching .exe: <error message>
```

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss improvements, bug fixes, or new features.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or feedback, please open an issue on the repository or contact the maintainer.
