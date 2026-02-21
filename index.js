#!/usr/bin/env node

/**
 * Wrike CLI - PAVE Secure Token Version
 * 
 * Query and manage Wrike tasks, folders, and attachments using secure token system.
 * Tokens are never visible to sandbox code - they're injected by the host.
 * 
 * Token configuration in ~/.pave/permissions.yaml:
 * {
 *   "tokens": {
 *     "wrike": {
 *       "env": "WRIKE_ACCESS_TOKEN",
 *       "type": "api_key",
 *       "domains": ["www.wrike.com", "*.wrike.com"],
 *       "placement": { "type": "header", "name": "Authorization", "format": "Bearer {token}" }
 *     }
 *   }
 * }
 */

// Constants
const WRIKE_HOST = 'www.wrike.com';
const WRIKE_API_BASE = `https://${WRIKE_HOST}/api/v4`;

// Common user mappings for convenience
const WRIKE_USERS = {
  'ALEX': 'KUAEMSKM',
  'ANNE': 'KUAVY32J',
  'CELINE': 'KUADC5LK',
  'CHRISTINE': 'KUARK5TX',
  'DAVID': 'KUAQ4TBX',
  'ERIC': 'KUAWCXOY',
  'FUNG': 'KUAIPTZ2',
  'HENRI': 'KUAFYGDH',
  'HONEY': 'KUAKUXLV',
  'JASMINE': 'KUADC57P',
  'JAZZ': 'KUAUB3C2',
  'KAYTON': 'KUAVZJZJ',
  'KELVIN': 'KUAT3J35',
  'KENNY': 'KUARI2JA',
  'MARTIN': 'KUAM7CWI',
  'NICOLE': 'KUAOHCP2',
  'OSCAR': 'KUAQUDOU',
  'RAYMOND': 'KUADC2JT',
  'STEPHEN': 'KUAKOPNI',
  'VESPER': 'KUAQXCZL',
  'ZUKI': 'KUAWJWNQ'
};

/**
 * URL encoding function for sandbox compatibility (no URLSearchParams)
 */
function encodeFormData(data) {
  const params = [];
  for (const [key, value] of Object.entries(data)) {
    if (value !== undefined && value !== null && value !== '') {
      params.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
    }
  }
  return params.join('&');
}

/**
 * Wrike API Client - Secure Token Version
 */
class WrikeClient {
  constructor() {
    // Check if wrike token is available via secure token system
    if (typeof hasToken === 'function' && !hasToken('wrike')) {
      console.error('Wrike token not configured.');
      console.error('');
      console.error('Add to ~/.pave/permissions.yaml under tokens section:');
      console.error(JSON.stringify({
        wrike: {
          env: 'WRIKE_ACCESS_TOKEN',
          type: 'api_key',
          domains: ['www.wrike.com', '*.wrike.com'],
          placement: { type: 'header', name: 'Authorization', format: 'Bearer {token}' }
        }
      }, null, 2));
      console.error('');
      console.error('Then set environment variable WRIKE_ACCESS_TOKEN');
      throw new Error('Wrike token not configured');
    }

    this.host = WRIKE_HOST;
    this.baseUrl = WRIKE_API_BASE;
  }

  /**
   * Make an authenticated request to the Wrike API
   */
  request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;

    const response = authenticatedFetch('wrike', url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      timeout: options.timeout || 30000
    });

    if (!response.ok) {
      let errorData;
      try {
        errorData = response.json();
      } catch (e) {
        errorData = { error: response.text() };
      }
      const err = new Error(errorData.errorDescription || errorData.error || `HTTP ${response.status}`);
      err.status = response.status;
      err.data = errorData;
      throw err;
    }

    return response.json();
  }

  /**
   * Extract numeric ID from a Wrike task URL
   */
  static extractIdFromUrl(url) {
    // Try URL parsing
    try {
      // Simple URL param extraction
      const match = url.match(/[?&]id=(\d+)/);
      return match ? match[1] : null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Resolve a user name to user ID
   */
  static resolveUserId(userInput) {
    const upper = userInput.toUpperCase();
    if (WRIKE_USERS[upper]) {
      return WRIKE_USERS[upper];
    }
    return userInput; // Return as-is if it's already an ID
  }

  /**
   * Query tasks with various filter parameters
   */
  queryTasks(params = {}) {
    const queryString = encodeFormData(params);
    const endpoint = '/tasks' + (queryString ? `?${queryString}` : '');
    return this.request(endpoint);
  }

  /**
   * Query tasks in a specific folder
   */
  queryTasksInFolder(folderId, params = {}) {
    const queryString = encodeFormData(params);
    const endpoint = `/folders/${folderId}/tasks` + (queryString ? `?${queryString}` : '');
    return this.request(endpoint);
  }

  /**
   * Query tasks in a specific space
   */
  queryTasksInSpace(spaceId, params = {}) {
    const queryString = encodeFormData(params);
    const endpoint = `/spaces/${spaceId}/tasks` + (queryString ? `?${queryString}` : '');
    return this.request(endpoint);
  }

  /**
   * Get specific tasks by their API IDs
   */
  getTasksByIds(taskIds) {
    if (!taskIds || taskIds.length === 0) {
      throw new Error('At least one task ID is required');
    }
    if (taskIds.length > 100) {
      throw new Error('Maximum 100 task IDs allowed per request');
    }
    const endpoint = `/tasks/${taskIds.join(',')}`;
    return this.request(endpoint);
  }

  /**
   * Get a task by its permalink ID
   */
  getTaskByPermalink(permalinkId) {
    const response = this.request(`/tasks?permalink=https://${this.host}/open.htm?id=${permalinkId}`);
    return response;
  }

  /**
   * Get tasks by their permalink IDs
   */
  getTasksByPermalinks(permalinkIds) {
    if (!permalinkIds || permalinkIds.length === 0) {
      throw new Error('At least one permalink ID is required');
    }

    const results = [];
    const errors = [];

    for (const permalinkId of permalinkIds) {
      try {
        const response = this.getTaskByPermalink(permalinkId);
        if (response.data && response.data.length > 0) {
          results.push(...response.data);
        }
      } catch (error) {
        errors.push({ permalinkId, error: error.message });
      }
    }

    return {
      kind: 'tasks',
      data: results,
      errors: errors.length > 0 ? errors : undefined
    };
  }

  /**
   * Get tasks from Wrike URLs
   */
  getTasksFromUrls(urls) {
    const permalinkIds = urls
      .map(url => WrikeClient.extractIdFromUrl(url))
      .filter(id => id !== null);

    if (permalinkIds.length === 0) {
      throw new Error('No valid task IDs found in the provided URLs');
    }

    return this.getTasksByPermalinks(permalinkIds);
  }

  /**
   * Create a new task in a folder
   */
  createTask(folderId, taskData) {
    const body = {};
    if (taskData.title) body.title = taskData.title;
    if (taskData.description) body.description = taskData.description;
    if (taskData.status) body.status = taskData.status;
    if (taskData.importance) body.importance = taskData.importance;
    if (taskData.responsibles) body.responsibles = taskData.responsibles;
    if (taskData.dates) body.dates = taskData.dates;

    return this.request(`/folders/${folderId}/tasks`, {
      method: 'POST',
      body: JSON.stringify(body)
    });
  }

  /**
   * Update an existing task
   */
  updateTask(taskId, taskData) {
    const body = {};
    if (taskData.title) body.title = taskData.title;
    if (taskData.description) body.description = taskData.description;
    if (taskData.status) body.status = taskData.status;
    if (taskData.importance) body.importance = taskData.importance;
    if (taskData.addResponsibles) body.addResponsibles = taskData.addResponsibles;
    if (taskData.removeResponsibles) body.removeResponsibles = taskData.removeResponsibles;
    if (taskData.responsibles) body.responsibles = taskData.responsibles;
    if (taskData.dates) body.dates = taskData.dates;

    return this.request(`/tasks/${taskId}`, {
      method: 'PUT',
      body: JSON.stringify(body)
    });
  }

  /**
   * Delete a task (move to trash)
   */
  deleteTask(taskId) {
    return this.request(`/tasks/${taskId}`, {
      method: 'DELETE'
    });
  }

  /**
   * Add a comment to a task
   */
  addComment(taskId, text, plainText = false) {
    return this.request(`/tasks/${taskId}/comments`, {
      method: 'POST',
      body: JSON.stringify({ text, plainText })
    });
  }

  /**
   * Get comments for a task
   */
  getComments(taskId) {
    return this.request(`/tasks/${taskId}/comments`);
  }

  /**
   * Get attachments for a task
   */
  getTaskAttachments(taskId) {
    return this.request(`/tasks/${taskId}/attachments`);
  }

  /**
   * Get attachments in a folder
   */
  getFolderAttachments(folderId, params = {}) {
    const queryString = encodeFormData(params);
    const endpoint = `/folders/${folderId}/attachments` + (queryString ? `?${queryString}` : '');
    return this.request(endpoint);
  }

  /**
   * Get all attachments (limited to last 31 days by default)
   */
  getAttachments(params = {}) {
    const queryString = encodeFormData(params);
    const endpoint = '/attachments' + (queryString ? `?${queryString}` : '');
    return this.request(endpoint);
  }

  /**
   * Search attachments by name
   */
  searchAttachmentsByName(searchName, options = {}) {
    let attachments;
    const params = {};
    if (options.createdDate) params.createdDate = options.createdDate;

    if (options.taskId) {
      attachments = this.getTaskAttachments(options.taskId);
    } else if (options.folderId) {
      attachments = this.getFolderAttachments(options.folderId, params);
    } else {
      attachments = this.getAttachments(params);
    }

    const searchLower = searchName.toLowerCase();
    const matchingAttachments = attachments.data.filter(attachment => {
      const name = attachment.name.toLowerCase();
      if (options.exact) {
        return name === searchLower;
      }
      return name.includes(searchLower);
    });

    return {
      kind: 'attachments',
      data: matchingAttachments,
      searchQuery: searchName,
      totalSearched: attachments.data.length,
      matchCount: matchingAttachments.length
    };
  }

  /**
   * Get contacts/users
   */
  getContacts(params = {}) {
    const queryString = encodeFormData(params);
    const endpoint = '/contacts' + (queryString ? `?${queryString}` : '');
    return this.request(endpoint);
  }

  /**
   * Get folders
   */
  getFolders(params = {}) {
    const queryString = encodeFormData(params);
    const endpoint = '/folders' + (queryString ? `?${queryString}` : '');
    return this.request(endpoint);
  }

  /**
   * Get folder by ID
   */
  getFolder(folderId) {
    return this.request(`/folders/${folderId}`);
  }

  /**
   * Get folder by permalink ID
   */
  getFolderByPermalink(permalinkId) {
    const response = this.request(`/folders?permalink=https://${this.host}/open.htm?id=${permalinkId}`);
    return response;
  }

  /**
   * Get spaces
   */
  getSpaces() {
    return this.request('/spaces');
  }

  /**
   * Convert numeric IDs to API IDs
   */
  convertIds(numericIds) {
    if (!numericIds || numericIds.length === 0) {
      return { data: [] };
    }
    const idsParam = numericIds.join(',');
    return this.request(`/ids?ids=[${idsParam}]&type=ApiV2Task`);
  }

  /**
   * Format task for human-readable output
   */
  static formatTask(task) {
    return {
      id: task.id,
      title: task.title,
      status: task.status,
      importance: task.importance,
      permalink: task.permalink,
      createdDate: task.createdDate,
      updatedDate: task.updatedDate,
      responsibleIds: task.responsibleIds || [],
      briefDescription: task.briefDescription || ''
    };
  }
}

/**
 * Parse command line arguments
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const parsed = {
    command: null,
    positional: [],
    options: {}
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const [key, value] = arg.slice(2).split('=', 2);
      if (value !== undefined) {
        parsed.options[key] = value;
      } else if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
        parsed.options[key] = args[i + 1];
        i++;
      } else {
        parsed.options[key] = true;
      }
    } else if (arg.startsWith('-')) {
      const flag = arg.slice(1);
      if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
        parsed.options[flag] = args[i + 1];
        i++;
      } else {
        parsed.options[flag] = true;
      }
    } else {
      if (parsed.command === null) {
        parsed.command = arg;
      } else {
        parsed.positional.push(arg);
      }
    }
  }

  return parsed;
}

/**
 * Print tasks summary
 */
function printTasksSummary(tasks) {
  if (!tasks || tasks.length === 0) {
    console.log('No tasks found.');
    return;
  }

  console.log(`Found ${tasks.length} task(s):\n`);

  tasks.forEach((task, index) => {
    const statusIcon = task.status === 'Completed' ? '✓' : 
                       task.status === 'Active' ? '●' : 
                       task.status === 'Deferred' ? '○' : '✗';
    
    console.log(`${index + 1}. [${statusIcon}] ${task.title}`);
    console.log(`   ID: ${task.id}`);
    console.log(`   Status: ${task.status} | Importance: ${task.importance || 'Normal'}`);
    
    if (task.responsibleIds && task.responsibleIds.length > 0) {
      console.log(`   Assigned to: ${task.responsibleIds.join(', ')}`);
    }
    
    if (task.permalink) {
      console.log(`   Link: ${task.permalink}`);
    }
    
    if (task.briefDescription) {
      console.log(`   Description: ${task.briefDescription.slice(0, 100)}...`);
    }
    
    console.log();
  });
}

/**
 * Print users summary
 */
function printUsersSummary(contacts) {
  const users = contacts.filter(c => c.type === 'Person' && !c.deleted);
  
  if (users.length === 0) {
    console.log('No users found.');
    return;
  }

  console.log('Wrike Users:\n');
  
  for (const user of users) {
    const name = `${user.firstName || ''} ${user.lastName || ''}`.trim() || '(no name)';
    const email = user.profiles && user.profiles[0] ? user.profiles[0].email : '(no email)';
    const meTag = user.me ? ' (you)' : '';
    console.log(`  ${user.id}: ${name} <${email}>${meTag}`);
  }
  
  console.log(`\nTotal: ${users.length} user(s)`);
}

/**
 * Print help message
 */
function printHelp() {
  console.log(`
Wrike CLI - PAVE Secure Token Version

USAGE:
  wrike <command> [options]

COMMANDS:
  query [options]              Query tasks with filters
  get [options]                Get specific tasks by IDs or URLs
  create [options]             Create a new task
  update [options]             Update a task
  delete [options]             Delete a task (move to trash)
  comment [options]            Add a comment to a task
  comments <taskId>            Get comments for a task
  assign [options]             Assign a task to user(s)
  attachments [options]        Query attachments
  users [options]              List Wrike users
  folders [options]            List folders
  spaces                       List spaces
  convert-id <ids>             Convert numeric IDs to API IDs
  extract-id <url>             Extract numeric ID from URL

QUERY OPTIONS:
  -f, --folder <folderId>      Filter by folder ID
  -s, --space <spaceId>        Filter by space ID
  --status <status>            Filter by status (Active, Completed, Deferred, Cancelled)
  --importance <importance>    Filter by importance (High, Normal, Low)
  --title <title>              Search by title
  --responsibles <ids>         Filter by assignee IDs (comma-separated)
  --sort-field <field>         Sort by field (CreatedDate, UpdatedDate, DueDate, etc.)
  --sort-order <order>         Sort order (Asc, Desc)
  --page-size <size>           Results per page (max 1000, default 100)

GET OPTIONS:
  -i, --ids <taskIds>          Task API IDs (comma-separated)
  -u, --urls <urls>            Wrike task URLs (comma-separated)

CREATE OPTIONS:
  -f, --folder <folderId>      Folder ID (required)
  -t, --title <title>          Task title (required)
  -d, --description <desc>     Task description
  --status <status>            Status (default: Active)
  --importance <importance>    Importance (default: Normal)
  --responsibles <ids>         Assign to users (comma-separated)

UPDATE OPTIONS:
  -i, --id <taskId>            Task API ID
  -u, --url <url>              Wrike task URL
  -t, --title <title>          New title
  -d, --description <desc>     New description
  --status <status>            New status
  --add-responsibles <ids>     Add assignees
  --remove-responsibles <ids>  Remove assignees

DELETE OPTIONS:
  -i, --id <taskId>            Task API ID
  -u, --url <url>              Wrike task URL

COMMENT OPTIONS:
  -i, --id <taskId>            Task API ID
  -u, --url <url>              Wrike task URL
  -m, --message <text>         Comment text (HTML supported)
  --plain                      Send as plain text

ASSIGN OPTIONS:
  -i, --id <taskId>            Task API ID
  -u, --url <url>              Wrike task URL
  --user <user>                User ID or name (e.g., KUADC57P or "jasmine")
  --replace                    Replace all existing assignees

ATTACHMENT OPTIONS:
  -t, --task <taskId>          Get attachments for a task
  --task-url <url>             Get attachments for a task by URL
  -f, --folder <folderId>      Get attachments in a folder
  --search <name>              Search attachments by name
  --exact                      Use exact name matching

USERS OPTIONS:
  --me                         Show only the current user

OUTPUT OPTIONS:
  --json                       Raw JSON output
  --summary                    Human-readable summary (default)

EXAMPLES:
  wrike query --folder MQAAAAECSW8i --status Active --summary
  wrike query --responsibles KUADC2JT --sort-field UpdatedDate --sort-order Desc
  wrike get --ids IEABSYMZI4E5E5JI --summary
  wrike get --urls "https://wrike.com/open.htm?id=123456"
  wrike create --folder MQAAAAECSW8i --title "New Task" --description "Details here"
  wrike update --id TASKID --status Completed
  wrike comment --id TASKID --message "Work completed<br/>Ready for review"
  wrike assign --url "https://wrike.com/..." --user jasmine
  wrike attachments --folder MQAAAAECSW8i --search "invoice"
  wrike users --summary
  wrike users --me

TOKEN SETUP:
  Requires WRIKE_ACCESS_TOKEN environment variable.
  Token is automatically injected via PAVE secure token system.
`);
}

/**
 * Main CLI execution
 */
function main() {
  const parsed = parseArgs();

  if (!parsed.command || parsed.command === 'help' || parsed.options.help) {
    printHelp();
    return;
  }

  try {
    const client = new WrikeClient();

    switch (parsed.command) {
      case 'query': {
        // Build query params
        const params = {};
        
        if (parsed.options.status) params.status = parsed.options.status;
        if (parsed.options.importance) params.importance = parsed.options.importance;
        if (parsed.options.title) params.title = parsed.options.title;
        if (parsed.options.authors) params.authors = `[${parsed.options.authors}]`;
        if (parsed.options.responsibles) params.responsibles = `[${parsed.options.responsibles}]`;
        if (parsed.options['start-date']) params.startDate = parsed.options['start-date'];
        if (parsed.options['due-date']) params.dueDate = parsed.options['due-date'];
        if (parsed.options['created-date']) params.createdDate = parsed.options['created-date'];
        if (parsed.options['updated-date']) params.updatedDate = parsed.options['updated-date'];
        if (parsed.options.type) params.type = parsed.options.type;
        if (parsed.options.subtasks) params.subTasks = 'true';
        if (parsed.options.descendants !== undefined) params.descendants = String(parsed.options.descendants);
        if (parsed.options['sort-field']) params.sortField = parsed.options['sort-field'];
        if (parsed.options['sort-order']) params.sortOrder = parsed.options['sort-order'];
        if (parsed.options['page-size']) params.pageSize = parsed.options['page-size'];
        if (parsed.options.fields) params.fields = `[${parsed.options.fields}]`;

        let result;
        if (parsed.options.folder || parsed.options.f) {
          result = client.queryTasksInFolder(parsed.options.folder || parsed.options.f, params);
        } else if (parsed.options.space || parsed.options.s) {
          result = client.queryTasksInSpace(parsed.options.space || parsed.options.s, params);
        } else {
          result = client.queryTasks(params);
        }

        if (parsed.options.summary) {
          printTasksSummary(result.data);
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'get': {
        if (!parsed.options.ids && !parsed.options.i && !parsed.options.urls && !parsed.options.u) {
          console.error('Error: Either --ids or --urls must be provided');
          process.exit(1);
        }

        let result;
        if (parsed.options.ids || parsed.options.i) {
          const taskIds = (parsed.options.ids || parsed.options.i).split(',').map(id => id.trim());
          result = client.getTasksByIds(taskIds);
        } else {
          const urls = (parsed.options.urls || parsed.options.u).split(',').map(url => url.trim());
          result = client.getTasksFromUrls(urls);
        }

        if (parsed.options.summary) {
          printTasksSummary(result.data);
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'create': {
        const folderId = parsed.options.folder || parsed.options.f;
        const title = parsed.options.title || parsed.options.t;

        if (!folderId) {
          console.error('Error: --folder is required');
          process.exit(1);
        }
        if (!title) {
          console.error('Error: --title is required');
          process.exit(1);
        }

        const taskData = {
          title: title,
          status: parsed.options.status || 'Active',
          importance: parsed.options.importance || 'Normal'
        };

        if (parsed.options.description || parsed.options.d) {
          taskData.description = parsed.options.description || parsed.options.d;
        }
        if (parsed.options.responsibles) {
          taskData.responsibles = parsed.options.responsibles.split(',').map(id => 
            WrikeClient.resolveUserId(id.trim())
          );
        }

        const result = client.createTask(folderId, taskData);

        if (parsed.options.summary) {
          const task = result.data[0];
          console.log(`Task created: ${task.title}`);
          console.log(`ID: ${task.id}`);
          console.log(`Link: ${task.permalink}`);
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'update': {
        if (!parsed.options.id && !parsed.options.i && !parsed.options.url && !parsed.options.u) {
          console.error('Error: Either --id or --url must be provided');
          process.exit(1);
        }

        let taskId = parsed.options.id || parsed.options.i;
        if (parsed.options.url || parsed.options.u) {
          const permalinkId = WrikeClient.extractIdFromUrl(parsed.options.url || parsed.options.u);
          if (!permalinkId) {
            console.error('Error: Could not extract ID from URL');
            process.exit(1);
          }
          const taskResponse = client.getTaskByPermalink(permalinkId);
          if (!taskResponse.data || taskResponse.data.length === 0) {
            console.error('Error: Task not found');
            process.exit(1);
          }
          taskId = taskResponse.data[0].id;
        }

        const updateData = {};
        if (parsed.options.title || parsed.options.t) updateData.title = parsed.options.title || parsed.options.t;
        if (parsed.options.description || parsed.options.d) updateData.description = parsed.options.description || parsed.options.d;
        if (parsed.options.status) updateData.status = parsed.options.status;
        if (parsed.options.importance) updateData.importance = parsed.options.importance;
        if (parsed.options['add-responsibles']) {
          updateData.addResponsibles = parsed.options['add-responsibles'].split(',').map(id => 
            WrikeClient.resolveUserId(id.trim())
          );
        }
        if (parsed.options['remove-responsibles']) {
          updateData.removeResponsibles = parsed.options['remove-responsibles'].split(',').map(id => 
            WrikeClient.resolveUserId(id.trim())
          );
        }

        const result = client.updateTask(taskId, updateData);

        if (parsed.options.summary) {
          const task = result.data[0];
          console.log(`Task updated: ${task.title}`);
          console.log(`Status: ${task.status}`);
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'delete': {
        if (!parsed.options.id && !parsed.options.i && !parsed.options.url && !parsed.options.u) {
          console.error('Error: Either --id or --url must be provided');
          process.exit(1);
        }

        let taskId = parsed.options.id || parsed.options.i;
        if (parsed.options.url || parsed.options.u) {
          const permalinkId = WrikeClient.extractIdFromUrl(parsed.options.url || parsed.options.u);
          if (!permalinkId) {
            console.error('Error: Could not extract ID from URL');
            process.exit(1);
          }
          const taskResponse = client.getTaskByPermalink(permalinkId);
          if (!taskResponse.data || taskResponse.data.length === 0) {
            console.error('Error: Task not found');
            process.exit(1);
          }
          taskId = taskResponse.data[0].id;
        }

        // Safety check - show task info before delete
        const taskInfo = client.getTasksByIds([taskId]);
        if (taskInfo.data && taskInfo.data.length > 0) {
          const task = taskInfo.data[0];
          console.log('About to delete task:');
          console.log(`  Title: ${task.title}`);
          console.log(`  ID: ${task.id}`);
          console.log(`  Link: ${task.permalink}`);
          console.log('');
        }

        const result = client.deleteTask(taskId);

        if (parsed.options.summary) {
          console.log(`Task deleted (moved to trash): ${taskId}`);
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'comment': {
        if (!parsed.options.id && !parsed.options.i && !parsed.options.url && !parsed.options.u) {
          console.error('Error: Either --id or --url must be provided');
          process.exit(1);
        }
        if (!parsed.options.message && !parsed.options.m) {
          console.error('Error: --message is required');
          process.exit(1);
        }

        let taskId = parsed.options.id || parsed.options.i;
        if (parsed.options.url || parsed.options.u) {
          const permalinkId = WrikeClient.extractIdFromUrl(parsed.options.url || parsed.options.u);
          if (!permalinkId) {
            console.error('Error: Could not extract ID from URL');
            process.exit(1);
          }
          const taskResponse = client.getTaskByPermalink(permalinkId);
          if (!taskResponse.data || taskResponse.data.length === 0) {
            console.error('Error: Task not found');
            process.exit(1);
          }
          taskId = taskResponse.data[0].id;
        }

        const message = parsed.options.message || parsed.options.m;
        const plainText = parsed.options.plain || false;

        const result = client.addComment(taskId, message, plainText);

        if (parsed.options.summary) {
          console.log(`Comment added to task: ${taskId}`);
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'comments': {
        const taskId = parsed.positional[0] || parsed.options.id || parsed.options.i;
        if (!taskId) {
          console.error('Error: Task ID required');
          console.error('Usage: wrike comments <taskId>');
          process.exit(1);
        }

        const result = client.getComments(taskId);

        if (parsed.options.summary) {
          const comments = result.data || [];
          if (comments.length === 0) {
            console.log('No comments found.');
          } else {
            console.log(`Found ${comments.length} comment(s):\n`);
            comments.forEach((comment, index) => {
              console.log(`${index + 1}. ${comment.authorId} (${comment.createdDate})`);
              console.log(`   ${comment.text.slice(0, 200)}${comment.text.length > 200 ? '...' : ''}`);
              console.log();
            });
          }
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'assign': {
        if (!parsed.options.id && !parsed.options.i && !parsed.options.url && !parsed.options.u) {
          console.error('Error: Either --id or --url must be provided');
          process.exit(1);
        }
        if (!parsed.options.user) {
          console.error('Error: --user is required');
          process.exit(1);
        }

        let taskId = parsed.options.id || parsed.options.i;
        if (parsed.options.url || parsed.options.u) {
          const permalinkId = WrikeClient.extractIdFromUrl(parsed.options.url || parsed.options.u);
          if (!permalinkId) {
            console.error('Error: Could not extract ID from URL');
            process.exit(1);
          }
          const taskResponse = client.getTaskByPermalink(permalinkId);
          if (!taskResponse.data || taskResponse.data.length === 0) {
            console.error('Error: Task not found');
            process.exit(1);
          }
          taskId = taskResponse.data[0].id;
        }

        const userId = WrikeClient.resolveUserId(parsed.options.user);
        const updateData = parsed.options.replace
          ? { responsibles: [userId] }
          : { addResponsibles: [userId] };

        const result = client.updateTask(taskId, updateData);

        const task = result.data && result.data[0];
        if (task && parsed.options.summary) {
          console.log(`Task "${task.title}" assigned to ${userId}`);
          console.log(`Responsibles: ${task.responsibleIds ? task.responsibleIds.join(', ') : 'none'}`);
        } else if (!parsed.options.summary) {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'attachments': {
        let result;

        // Resolve task URL to task ID if provided
        let taskId = parsed.options.task || parsed.options.t;
        if (parsed.options['task-url']) {
          const permalinkId = WrikeClient.extractIdFromUrl(parsed.options['task-url']);
          if (!permalinkId) {
            console.error('Error: Could not extract ID from task URL');
            process.exit(1);
          }
          const taskResponse = client.getTaskByPermalink(permalinkId);
          if (!taskResponse.data || taskResponse.data.length === 0) {
            console.error('Error: Task not found');
            process.exit(1);
          }
          taskId = taskResponse.data[0].id;
        }

        if (parsed.options.search) {
          const searchOptions = {
            exact: parsed.options.exact || false
          };
          if (taskId) searchOptions.taskId = taskId;
          if (parsed.options.folder || parsed.options.f) {
            searchOptions.folderId = parsed.options.folder || parsed.options.f;
          }
          result = client.searchAttachmentsByName(parsed.options.search, searchOptions);
        } else if (taskId) {
          result = client.getTaskAttachments(taskId);
        } else if (parsed.options.folder || parsed.options.f) {
          result = client.getFolderAttachments(parsed.options.folder || parsed.options.f);
        } else {
          result = client.getAttachments();
        }

        if (parsed.options.summary) {
          const attachments = result.data || [];
          if (attachments.length === 0) {
            console.log('No attachments found.');
          } else {
            console.log(`Found ${attachments.length} attachment(s):\n`);
            attachments.forEach((att, index) => {
              console.log(`${index + 1}. ${att.name}`);
              console.log(`   ID: ${att.id}`);
              console.log(`   Size: ${att.size || 'unknown'} bytes`);
              console.log(`   Type: ${att.contentType || 'unknown'}`);
              console.log();
            });
          }
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'users': {
        const params = {};
        if (parsed.options.me) params.me = true;

        const result = client.getContacts(params);

        if (parsed.options.summary) {
          printUsersSummary(result.data || []);
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'folders': {
        const result = client.getFolders();

        if (parsed.options.summary) {
          const folders = result.data || [];
          if (folders.length === 0) {
            console.log('No folders found.');
          } else {
            console.log(`Found ${folders.length} folder(s):\n`);
            folders.forEach((folder, index) => {
              console.log(`${index + 1}. ${folder.title}`);
              console.log(`   ID: ${folder.id}`);
              console.log();
            });
          }
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'spaces': {
        const result = client.getSpaces();

        if (parsed.options.summary) {
          const spaces = result.data || [];
          if (spaces.length === 0) {
            console.log('No spaces found.');
          } else {
            console.log(`Found ${spaces.length} space(s):\n`);
            spaces.forEach((space, index) => {
              console.log(`${index + 1}. ${space.title}`);
              console.log(`   ID: ${space.id}`);
              console.log();
            });
          }
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'convert-id': {
        const ids = parsed.positional[0];
        if (!ids) {
          console.error('Error: IDs required');
          console.error('Usage: wrike convert-id <ids>');
          process.exit(1);
        }

        const numericIds = ids.split(',').map(id => id.trim());
        const result = client.convertIds(numericIds);
        console.log(JSON.stringify(result, null, 2));
        break;
      }

      case 'extract-id': {
        const url = parsed.positional[0];
        if (!url) {
          console.error('Error: URL required');
          console.error('Usage: wrike extract-id <url>');
          process.exit(1);
        }

        const id = WrikeClient.extractIdFromUrl(url);
        if (id) {
          console.log(JSON.stringify({ numericId: id }, null, 2));
        } else {
          console.error(JSON.stringify({ error: 'Could not extract ID from URL' }, null, 2));
          process.exit(1);
        }
        break;
      }

      default:
        console.error(`Error: Unknown command '${parsed.command}'`);
        console.error('\nRun: wrike help');
        process.exit(1);
    }

  } catch (error) {
    if (parsed.options.summary) {
      console.error(`Wrike Error: ${error.message}`);
    } else {
      console.error(JSON.stringify({
        error: error.message,
        status: error.status,
        data: error.data
      }, null, 2));
    }
    process.exit(1);
  }
}

// Execute
main();

module.exports = { WrikeClient, WRIKE_USERS };
