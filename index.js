#!/usr/bin/env node

/**
 * Wrike CLI - PAVE Secure Token Version
 * 
 * Query and manage Wrike tasks, folders, and attachments using secure token system.
 * Tokens are never visible to sandbox code - they're injected by the host.
 * 
 * Token configuration in ~/.pave/permissions.yaml:
 * 
 * tokens:
 *   wrike:
 *     env: WRIKE_ACCESS_TOKEN
 *     type: api_key
 *     domains:
 *       - www.wrike.com
 *       - "*.wrike.com"
 *     placement:
 *       type: header
 *       name: Authorization
 *       format: "Bearer {token}"
 */

// Constants
const WRIKE_HOST = 'www.wrike.com';
const WRIKE_API_BASE = `https://${WRIKE_HOST}/api/v4`;
const fs = require('fs');
const path = require('path');
const os = require('os');

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

// ── PAVE Auth Proxy (replaces deprecated authenticatedFetch global) ──
// Direct HTTP calls to the PAVE auth proxy at /proxy/:tokenName/*path
var PAVE_PROXY_BASE = process.env.PAVE_PROXY_URL || '';

// Request bodies must never travel in argv. execve caps a single argument at
// MAX_ARG_STRLEN (128 KiB on Linux) and the whole argv+env at ARG_MAX (1 MB on
// macOS), so a large body fails with E2BIG before curl even starts. Bodies
// above this limit are spilled to a temp file and streamed with
// --data-binary @file; smaller ones stay inline.
var BODY_ARG_LIMIT = 32 * 1024;

function proxyHasToken(tokenName) {
  if (!PAVE_PROXY_BASE) return false;
  try {
    var url = PAVE_PROXY_BASE.replace(/\/$/, '') + '/_tokens/' + encodeURIComponent(tokenName);
    var out = require('child_process').execFileSync(
      'curl', ['-sS', '--max-time', '5', url],
      { encoding: 'utf8', timeout: 8000, stdio: ['pipe', 'pipe', 'pipe'] }
    );
    var r = JSON.parse(out);
    return r.has === true;
  } catch (e) {
    return false;
  }
}

// Spill a request body to disk and stream it with --data-binary @file.
//
// Two runtime constraints, both verified against the real sandbox:
//  - process.pid is undefined inside the PAVE sandbox, so the file name must not
//    depend on it;
//  - the sandbox refuses to unlink an absolute path with fewer than 3 path
//    components, so /tmp/<file>.tmp can be written but NOT deleted. Files live in
//    a dedicated subdirectory instead.
const PROXY_BODY_DIR = path.join(os.tmpdir(), 'pave-proxy-bodies');
function _writeProxyBodyFile(bodyStr) {
  try { fs.mkdirSync(PROXY_BODY_DIR, { recursive: true }); } catch (e) { /* already exists */ }
  const p = path.join(PROXY_BODY_DIR,
    'body-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10) + '.tmp');
  fs.writeFileSync(p, bodyStr, { mode: 384 }); // 0600
  return p;
}
function _removeProxyBodyFile(p) {
  try { fs.unlinkSync(p); return; } catch (e) { /* fall through */ }
  try { if (typeof fs.rmSync === 'function') fs.rmSync(p, { force: true }); } catch (e) { /* best effort */ }
}

function proxyFetch(tokenName, url, options) {
  options = options || {};
  if (!PAVE_PROXY_BASE) {
    throw new Error('PAVE_PROXY_URL not set - cannot reach auth proxy');
  }

  var parsed = new URL(url);
  var proxyUrl = PAVE_PROXY_BASE.replace(/\/$/, '') + '/' + encodeURIComponent(tokenName) + parsed.pathname + parsed.search;
  proxyUrl += (proxyUrl.indexOf('?') !== -1 ? '&' : '?') + '_mode=json';
  if (options.saveTo) {
    proxyUrl += '&_saveTo=' + encodeURIComponent(options.saveTo);
  }

  var method = options.method || 'GET';
  var timeout = options.timeout || 30000;
  var argv = ['-sS', '-X', method, '--max-time', String(Math.ceil(timeout / 1000))];

  var headers = Object.assign({}, options.headers || {});
  if (options.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  for (var k in headers) {
    argv.push('-H', k + ': ' + headers[k]);
  }

  // Bodies must never travel in argv — see the BODY_ARG_LIMIT note above.
  var bodyFile = options.bodyFile || null;
  var tempBodyFile = null;
  if (!bodyFile && options.body) {
    var bodyStr = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
    if (bodyStr.length > BODY_ARG_LIMIT) {
      tempBodyFile = _writeProxyBodyFile(bodyStr);
      bodyFile = tempBodyFile;
    } else {
      argv.push('-d', bodyStr);
    }
  }

  if (bodyFile) {
    argv.push('--data-binary', '@' + bodyFile);
  }

  argv.push(proxyUrl);

  var out;
  try {
    out = require('child_process').execFileSync('curl', argv, {
      encoding: 'utf8', timeout: timeout + 5000, maxBuffer: 10 * 1024 * 1024,
      stdio: ['pipe', 'pipe', 'pipe']
    });
  } catch (err) {
    var stdout = err.stdout ? err.stdout.toString() : '';
    var stderr = err.stderr ? err.stderr.toString() : '';
    if (stdout) { out = stdout; } else {
      throw new Error('Proxy request failed: ' + (stderr.trim() || err.message));
    }
  } finally {
    if (tempBodyFile) { _removeProxyBodyFile(tempBodyFile); }
  }

  var resp;
  try { resp = JSON.parse(out); } catch (e) {
    return { ok: true, status: 200, headers: { get: function() { return null; } },
      text: function() { return out; }, json: function() { return JSON.parse(out || '{}'); } };
  }
  if (resp.error) throw new Error(resp.error);
  if (resp.savedTo) {
    return { ok: resp.ok || false, status: resp.status || 200, savedTo: resp.savedTo,
      size: resp.size,
      headers: { get: function() { return null; } },
      text: function() { return ''; }, json: function() { return {}; } };
  }
  return { ok: resp.ok || false, status: resp.status || 200,
    headers: { get: function(name) { var hs = resp.headers || {}, ln = name.toLowerCase();
      for (var key in hs) { if (key.toLowerCase() === ln) return Array.isArray(hs[key]) ? hs[key][0] : hs[key]; }
      return null; } },
    text: function() { return resp.body || ''; }, json: function() { return JSON.parse(resp.body || '{}'); } };
}

class WrikeClient {
  constructor() {
    // Check if wrike token is available via secure token system
    if (!proxyHasToken('wrike')) {
      console.error('Wrike token not configured.');
      console.error('');
      console.error('Add to ~/.pave/permissions.yaml under tokens section:');
      console.error('');
      console.error('tokens:');
      console.error('  wrike:');
      console.error('    env: WRIKE_ACCESS_TOKEN');
      console.error('    type: api_key');
      console.error('    domains:');
      console.error('      - www.wrike.com');
      console.error('      - "*.wrike.com"');
      console.error('    placement:');
      console.error('      type: header');
      console.error('      name: Authorization');
      console.error('      format: "Bearer {token}"');
      console.error('');
      console.error('Then add your token to ~/.pave/tokens.yaml:');
      console.error('');
      console.error('WRIKE_ACCESS_TOKEN: "your-wrike-permanent-access-token"');
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

    const response = proxyFetch('wrike', url, {
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
   * Converts newlines to <br> tags for proper HTML rendering in Wrike
   */
  addComment(taskId, text, plainText = false) {
    // Convert newlines to <br> for HTML mode (Wrike default)
    // This ensures line breaks are preserved in the comment
    const formattedText = plainText ? text : text.replace(/\n/g, '<br>');
    
    return this.request(`/tasks/${taskId}/comments`, {
      method: 'POST',
      body: JSON.stringify({ text: formattedText, plainText })
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
   * Get a single attachment's metadata by ID (name, size, contentType)
   */
  getAttachment(attachmentId) {
    const response = this.request(`/attachments/${encodeURIComponent(attachmentId)}`);
    const attachment = response.data && response.data[0];
    if (!attachment) {
      throw new Error(`Attachment not found: ${attachmentId}`);
    }
    return attachment;
  }

  /**
   * Download an attachment's binary content to a local file (#2185).
   *
   * Uses the PAVE auth proxy's _saveTo mode: the trusted host follows the
   * Wrike 302 to the presigned download URL, streams the body to disk
   * binary-safe, and injects the Authorization header — the sandboxed skill
   * never sees the token or the bytes. savePath must resolve under the
   * user's home directory or /tmp or the proxy rejects it with 403.
   */
  downloadAttachment(attachmentId, savePath) {
    const url = `https://${this.host}/api/v4/attachments/${encodeURIComponent(attachmentId)}/download`;
    const response = proxyFetch('wrike', url, {
      saveTo: savePath,
      timeout: 120000
    });

    if (!response.ok || !response.savedTo) {
      // The proxy writes the upstream (error) body to the file even on
      // failure — surface it and clean up so a bogus file doesn't linger.
      let detail = '';
      try {
        const fs = require('fs');
        const written = response.savedTo || savePath;
        detail = fs.readFileSync(written, 'utf8').slice(0, 300);
        try { fs.unlinkSync(written); } catch (e) { /* best effort */ }
      } catch (e) { /* best effort */ }
      const err = new Error(`Attachment download failed (HTTP ${response.status})${detail ? ': ' + detail : ''}`);
      err.status = response.status;
      throw err;
    }

    return {
      attachmentId: attachmentId,
      savedTo: response.savedTo,
      size: response.size
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
   * Get folders (simple — no fields param, returns raw API response)
   */
  getFolders(params = {}) {
    const queryString = encodeFormData(params);
    const endpoint = '/folders' + (queryString ? `?${queryString}` : '');
    return this.request(endpoint);
  }

  /**
   * Get all folders. The /folders endpoint returns the folder tree in a single
   * response (no pagination supported), but accepts a `fields` parameter to
   * request additional metadata such as `project` so we can detect projects.
   */
  getAllFolders(params = {}) {
    const qs = encodeFormData(params);
    const endpoint = '/folders' + (qs ? `?${qs}` : '');
    const resp = this.request(endpoint);
    return { kind: resp.kind || 'folderTree', data: resp.data || [] };
  }

  /**
   * Get folders inside a specific space or folder (supports descendants).
   * Useful for listing all projects under a space.
   */
  getFoldersIn(parentId, params = {}) {
    const qs = encodeFormData(params);
    const endpoint = `/folders/${parentId}/folders` + (qs ? `?${qs}` : '');
    const resp = this.request(endpoint);
    return { kind: resp.kind || 'folderTree', data: resp.data || [] };
  }

  /**
   * Get folders within a space.
   */
  getSpaceFolders(spaceId, params = {}) {
    const qs = encodeFormData(params);
    const endpoint = `/spaces/${spaceId}/folders` + (qs ? `?${qs}` : '');
    const resp = this.request(endpoint);
    return { kind: resp.kind || 'folderTree', data: resp.data || [] };
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
  download [options]           Download an attachment to local disk (authenticated)
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
  -d, --description <desc>     Task description (single-line; avoid apostrophes)
  --description-file <path>    Read description from file (preferred for multi-line / HTML)
  --status <status>            Status (default: Active)
  --importance <importance>    Importance (default: Normal)
  --responsibles <ids>         Assign to users (comma-separated)

UPDATE OPTIONS:
  -i, --id <taskId>            Task API ID
  -u, --url <url>              Wrike task URL
  -t, --title <title>          New title
  -d, --description <desc>     New description (single-line; avoid apostrophes)
  --description-file <path>    Read new description from file (preferred for multi-line / HTML)
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

DOWNLOAD OPTIONS:
  -i, --attachment <id>        Download by attachment API ID
  -t, --task <taskId>          Find attachment on this task (with --search)
  --task-url <url>             Find attachment on this task URL (with --search)
  -f, --folder <folderId>      Search attachments in a folder (with --search)
  --search <name>              Attachment name to download (must match exactly one)
  --exact                      Use exact name matching
  -o, --output <path>          Save path (default: ~/Downloads/<attachment name>)

USERS OPTIONS:
  --me                         Show only the current user

FOLDERS OPTIONS:
  -s, --space <spaceId>        List folders/projects in a space
  -p, --parent <folderId>      List children of a folder/project
  --projects                   Include project metadata + filter to projects only
  --project-only               Alias for --projects (projects only)
  --search <text>              Case-insensitive title contains filter
  --fields <fields>            Comma-separated extra fields (e.g. project,customFields)
  --deleted                    Include deleted folders

OUTPUT OPTIONS:
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
  wrike download --task-url "https://www.wrike.com/open.htm?id=123456" --search "invoice" --exact
  wrike download --attachment IEABSYMZI4E5E5JI
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

        // Pagination: default 50 per page, use --page-token for subsequent pages
        const pageSize = parsed.options['page-size'] || '50';
        params.pageSize = pageSize;
        if (parsed.options['page-token']) params.nextPageToken = parsed.options['page-token'];
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
          const tasks = (result.data || []).map(t => ({
            id: t.id,
            title: t.title,
            status: t.status,
            importance: t.importance,
            permalink: t.permalink,
            responsibleIds: t.responsibleIds,
          }));
          const compact = {
            kind: 'tasks',
            count: tasks.length,
            pageSize: parseInt(pageSize, 10),
            nextPageToken: result.nextPageToken || null,
            tasks,
          };
          if (result.nextPageToken) {
            compact.tip = 'Use --page-token ' + result.nextPageToken + ' to get the next page';
          } else {
            compact.tip = 'No more pages. Use "get" with specific task IDs for full details, or --summary for readable list';
          }
          console.log(JSON.stringify(compact));
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
          console.log(JSON.stringify(result));
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

        if (parsed.options['description-file']) {
          const fs = require('fs');
          taskData.description = fs.readFileSync(parsed.options['description-file'], 'utf8');
        } else if (parsed.options.description || parsed.options.d) {
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
          console.log(JSON.stringify(result));
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
        if (parsed.options['description-file']) {
          const fs = require('fs');
          updateData.description = fs.readFileSync(parsed.options['description-file'], 'utf8');
        } else if (parsed.options.description || parsed.options.d) {
          updateData.description = parsed.options.description || parsed.options.d;
        }
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
          console.log(JSON.stringify(result));
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
        if (parsed.options.summary) {
          const taskInfo = client.getTasksByIds([taskId]);
          if (taskInfo.data && taskInfo.data.length > 0) {
            const task = taskInfo.data[0];
            console.log('About to delete task:');
            console.log(`  Title: ${task.title}`);
            console.log(`  ID: ${task.id}`);
            console.log(`  Link: ${task.permalink}`);
            console.log('');
          }
        }

        const result = client.deleteTask(taskId);

        if (parsed.options.summary) {
          console.log(`Task deleted (moved to trash): ${taskId}`);
        } else {
          console.log(JSON.stringify(result));
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
          console.log(JSON.stringify(result));
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
          console.log(JSON.stringify(result));
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
          console.log(JSON.stringify(result));
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
          console.log(JSON.stringify(result));
        }
        break;
      }

      case 'download': {
        const attachmentIdOpt = parsed.options.attachment || parsed.options.i;
        const searchName = parsed.options.search;
        const outputOpt = parsed.options.output || parsed.options.o;

        if (!attachmentIdOpt && !searchName) {
          console.error('Error: Either --attachment <id> or --search <name> must be provided');
          console.error('Usage: wrike download -i <attachmentId>');
          console.error('       wrike download --task-url <url> --search <name>');
          process.exit(1);
        }

        let attachment;
        if (attachmentIdOpt) {
          attachment = client.getAttachment(attachmentIdOpt);
        } else {
          // Resolve task URL to task ID if provided (same pattern as attachments)
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

          const searchOptions = { exact: parsed.options.exact || false };
          if (taskId) searchOptions.taskId = taskId;
          if (parsed.options.folder || parsed.options.f) {
            searchOptions.folderId = parsed.options.folder || parsed.options.f;
          }

          const searchResult = client.searchAttachmentsByName(searchName, searchOptions);
          if (searchResult.matchCount === 0) {
            console.error(`Error: No attachment matching "${searchName}" found (searched ${searchResult.totalSearched} attachment(s))`);
            console.error('Run "wrike attachments" with the same filters to list names and IDs');
            process.exit(1);
          }
          if (searchResult.matchCount > 1) {
            console.error(`Error: ${searchResult.matchCount} attachments match "${searchName}" — use --exact or pick one by ID:\n`);
            searchResult.data.forEach((att, index) => {
              console.error(`  ${index + 1}. ${att.name} (ID: ${att.id}, ${att.size || '?'} bytes)`);
            });
            process.exit(1);
          }
          attachment = searchResult.data[0];
        }

        // Resolve save path: explicit --output wins; default ~/Downloads/<attachment name>
        const path = require('path');
        const homeDir = process.env.HOME || process.env.USERPROFILE;
        let savePath = outputOpt;
        if (!savePath) {
          if (!homeDir) {
            console.error('Error: --output <path> required (cannot determine home directory for the default location)');
            process.exit(1);
          }
          const fallbackName = `attachment-${attachment.id}`;
          const safeName = String(attachment.name || fallbackName).replace(/[/\\:*?"<>|\u0000]/g, '_').trim() || fallbackName;
          savePath = path.join(homeDir, 'Downloads', safeName);
        } else if (savePath.startsWith('~/') || savePath === '~') {
          if (!homeDir) {
            console.error('Error: Cannot expand ~ without a home directory');
            process.exit(1);
          }
          savePath = savePath === '~' ? homeDir : path.join(homeDir, savePath.slice(2));
        } else {
          savePath = path.resolve(savePath);
        }

        // Don't clobber an existing file: append -2, -3, ... before the extension
        try {
          const fs = require('fs');
          if (fs.existsSync(savePath)) {
            const ext = path.extname(savePath);
            const stem = savePath.slice(0, savePath.length - ext.length);
            let n = 2;
            while (fs.existsSync(`${stem}-${n}${ext}`)) n++;
            savePath = `${stem}-${n}${ext}`;
          }
        } catch (e) { /* fall through with the original path */ }

        const result = client.downloadAttachment(attachment.id, savePath);

        if (parsed.options.summary) {
          console.log(`Downloaded "${attachment.name}"`);
          console.log(`  Saved to: ${result.savedTo}`);
          console.log(`  Size: ${result.size} bytes`);
          if (attachment.contentType) console.log(`  Type: ${attachment.contentType}`);
        } else {
          console.log(JSON.stringify({
            kind: 'download',
            attachmentId: attachment.id,
            name: attachment.name,
            contentType: attachment.contentType,
            size: result.size,
            savedTo: result.savedTo
          }));
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
          console.log(JSON.stringify(result));
        }
        break;
      }

      case 'folders': {
        const params = {};
        // --projects / --project-only: filter client-side (project data is in default response)
        const wantProjects = !!parsed.options['projects'] || !!parsed.options['project-only'];
        const fieldsOpt = parsed.options.fields;
        const fields = [];
        // Only add user-specified fields; 'project' is already returned by default
        if (fieldsOpt) {
          String(fieldsOpt).split(',').map(s => s.trim()).filter(Boolean).forEach(f => {
            if (!fields.includes(f)) fields.push(f);
          });
        }
        if (fields.length) params.fields = JSON.stringify(fields);
        if (parsed.options.descendants === 'false' || parsed.options.descendants === false) {
          params.descendants = false;
        }
        if (parsed.options.deleted) params.deleted = true;

        const space = parsed.options.space || parsed.options.s;
        const parent = parsed.options.parent || parsed.options.p;
        const search = (parsed.options.search || '').toString().toLowerCase();

        let result;
        if (space) {
          result = client.getSpaceFolders(space, params);
        } else if (parent) {
          result = client.getFoldersIn(parent, params);
        } else {
          result = client.getAllFolders(params);
        }

        let folders = result.data || [];
        if (wantProjects) {
          folders = folders.filter(f => f.project);
        }
        if (search) {
          folders = folders.filter(f => (f.title || '').toLowerCase().includes(search));
        }

        if (parsed.options.summary) {
          if (folders.length === 0) {
            console.log('No folders found.');
          } else {
            console.log(`Found ${folders.length} folder(s):\n`);
            folders.forEach((folder, index) => {
              const kind = folder.project ? '[Project]' : '[Folder]';
              console.log(`${index + 1}. ${kind} ${folder.title}`);
              console.log(`   ID: ${folder.id}`);
              if (folder.project) {
                const proj = folder.project;
                const status = proj.customStatusId ? `customStatus:${proj.customStatusId}` : (proj.status || '');
                console.log(`   Project: ${status}${proj.ownerIds ? ' | owners: ' + proj.ownerIds.join(',') : ''}`);
              }
              if (folder.permalink) console.log(`   Link: ${folder.permalink}`);
              console.log();
            });
          }
        } else {
          console.log(JSON.stringify({ kind: result.kind || 'folderTree', count: folders.length, data: folders }));
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
          console.log(JSON.stringify(result));
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
        console.log(JSON.stringify(result));
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
          console.log(JSON.stringify({ numericId: id }));
        } else {
          console.error(JSON.stringify({ error: 'Could not extract ID from URL' }));
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
      }));
    }
    process.exit(1);
  }
}

// Execute
main();

module.exports = { WrikeClient, WRIKE_USERS };
