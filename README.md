# OpenPAVE Wrike Skill

Query and manage Wrike tasks, folders, and attachments using the PAVE secure token system.

## Installation

```bash
pave install openpave-wrike
```

## Token Configuration

Add your Wrike access token to `~/.pave/tokens.yaml`:

```yaml
WRIKE_ACCESS_TOKEN: "your-wrike-permanent-access-token"
```

The token configuration is automatically set up in `~/.pave/permissions.yaml`:

```json
{
  "tokens": {
    "wrike": {
      "env": "WRIKE_ACCESS_TOKEN",
      "type": "api_key",
      "domains": ["www.wrike.com", "*.wrike.com"],
      "placement": {
        "type": "header",
        "name": "Authorization",
        "format": "Bearer {token}"
      }
    }
  }
}
```

## Usage

### Query Tasks

```bash
# Query all active tasks
wrike query --status Active --summary

# Query tasks in a specific folder
wrike query --folder MQAAAAECSW8i --status Active --summary

# Query tasks assigned to a user
wrike query --responsibles KUADC2JT --sort-field UpdatedDate --sort-order Desc --summary

# Query tasks in a space
wrike query --space SPACEID --status Active --summary
```

### Get Specific Tasks

```bash
# Get tasks by API IDs
wrike get --ids IEABSYMZI4E5E5JI,IEABSYMZI4E5E5JJ --summary

# Get tasks by Wrike URLs
wrike get --urls "https://www.wrike.com/open.htm?id=123456" --summary
```

### Create Tasks

```bash
# Create a basic task
wrike create --folder MQAAAAECSW8i --title "New Task" --summary

# Create a task with description and assignees
wrike create --folder MQAAAAECSW8i --title "Review PR" \
  --description "Please review the pull request" \
  --responsibles jasmine,raymond \
  --importance High
```

### Update Tasks

```bash
# Update task status
wrike update --id TASKID --status Completed

# Update task by URL
wrike update --url "https://wrike.com/open.htm?id=123456" --status Active

# Add assignees
wrike update --id TASKID --add-responsibles jasmine

# Change title and importance
wrike update --id TASKID --title "Updated Title" --importance High
```

### Delete Tasks

```bash
# Delete by ID (moves to trash)
wrike delete --id TASKID

# Delete by URL
wrike delete --url "https://wrike.com/open.htm?id=123456"
```

### Comments

```bash
# Add a comment (HTML supported)
wrike comment --id TASKID --message "Work completed<br/><b>Ready for review</b>"

# Add plain text comment
wrike comment --id TASKID --message "Plain text comment" --plain

# Get comments for a task
wrike comments TASKID --summary
```

### Assign Tasks

```bash
# Assign by user name
wrike assign --url "https://wrike.com/..." --user jasmine

# Assign by user ID
wrike assign --id TASKID --user KUADC57P

# Replace all assignees
wrike assign --id TASKID --user jasmine --replace
```

### Attachments

```bash
# List all attachments (last 31 days)
wrike attachments --summary

# Get attachments for a task
wrike attachments --task TASKID --summary

# Search attachments by name
wrike attachments --folder MQAAAAECSW8i --search "invoice" --summary

# Exact name match
wrike attachments --search "report.pdf" --exact --summary
```

### Users and Organization

```bash
# List all users
wrike users --summary

# Show current user
wrike users --me --summary

# List all folders
wrike folders --summary

# List all spaces
wrike spaces --summary
```

### Utility Commands

```bash
# Convert numeric IDs to API IDs
wrike convert-id 4340671950,4340671951

# Extract ID from URL (offline)
wrike extract-id "https://www.wrike.com/open.htm?id=4340671950"
```

## Query Options

| Option | Description |
|--------|-------------|
| `-f, --folder <id>` | Filter by folder ID |
| `-s, --space <id>` | Filter by space ID |
| `--status <status>` | Active, Completed, Deferred, Cancelled |
| `--importance <level>` | High, Normal, Low |
| `--title <search>` | Search by title |
| `--responsibles <ids>` | Filter by assignee IDs |
| `--sort-field <field>` | CreatedDate, UpdatedDate, DueDate, etc. |
| `--sort-order <order>` | Asc, Desc |
| `--page-size <num>` | Results per page (max 1000) |

## Common Folder IDs

| Folder | ID |
|--------|-----|
| Daily Scrum | `MQAAAAECSW8i` |
| Under Radar (CEO Desk) | `MQAAAAECSOwP` |
| cnr-pipedrive | `IEABSYMZI4E5E5JI` |

## User Name Mappings

You can use user names instead of IDs for convenience:

| Name | ID |
|------|-----|
| Alex | KUAEMSKM |
| Anne | KUAVY32J |
| Jasmine | KUADC57P |
| Raymond | KUADC2JT |
| ... | (see index.js for full list) |

## Output Formats

- `--summary` - Human-readable output (default for most commands)
- `--json` - Raw JSON response

## Comment Formatting

When posting comments, use HTML formatting:

| Format | HTML |
|--------|------|
| Line break | `<br/>` |
| Bold | `<b>text</b>` |
| Italic | `<i>text</i>` |
| Link | `<a href="url">text</a>` |
| List | `<ul><li>item</li></ul>` |

## License

MIT
