 **UniqueRequest** is a Burp Suite extension that helps security professionals filter and identify unique HTTP requests across normal and GraphQL traffic. It normalizes request paths and identifies unique patterns using a hash-based deduplication system. The extension also includes filtering by request type (GET/POST), file extension exclusion, and support for viewing GraphQL operations.

## Features  
- Separate modes for:
  - **Normal Requests** (non-GraphQL traffic)
  - **GraphQL Requests** (identifies GraphQL operations from body)
- Normalization of request paths for better pattern matching
- Filtering options for:
  - GET/POST requests
  - Requests with/without static file extensions
- Request/Response viewer
- Search field for real-time filtering
- Right-click context menu for:
  - Sending to Repeater
  - Clearing specific rows
- GUI toggle between Normal and GraphQL mode
- Results displayed in sortable tables

## Requirements  
- Burp Suite Professional or Community Edition  
- Jython 2.7.x standalone JAR  
- Java 8+

## Installation  
1. Download the UniqueRequest.py File
2. Load the extension via the **Extender** tab in Burp Suite.
3. Set the extension type to **Python**.
4. Load this extension file.

## Usage  
- Go to the **UniqueRequest** tab in Burp Suite.
- Choose a mode: **Normal Requests** or **GraphQL Requests** using the toggle buttons.
- Click **Start** to begin analysis of proxy history.
- Use the **Filter** button (Normal mode only) to include/exclude GET, POST, or static file types.
- Use the **Search** box to filter by normalized path or GraphQL operation name.
- Right-click on any row to:
  - Send the request to the Repeater
  - Clear the selected row
- Click **Clear All** to reset the table.
