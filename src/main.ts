import {
  ADMIN_SECTIONS,
  AdminClientError,
  createAdminClient,
  type AdminResource,
  type AdminResourceRow,
  type AdminSection,
  type AdminWriteCapability,
} from "./admin-client.js";

function requiredElement<T extends HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (element === null) throw new Error("Orbit Admin document is missing a required element.");
  return element;
}

const navigation = requiredElement<HTMLElement>("#section-navigation");
const resourceNavigation = requiredElement<HTMLElement>("#resource-navigation");
const resourceEmpty = requiredElement<HTMLElement>("#resource-empty");
const title = requiredElement<HTMLElement>("#view-title");
const description = requiredElement<HTMLElement>("#view-description");
const dataTitle = requiredElement<HTMLElement>("#data-title");
const accessMode = requiredElement<HTMLElement>("#access-mode");
const dataView = requiredElement<HTMLElement>("#data-view");
const resourceTableView = requiredElement<HTMLElement>("#resource-table-view");
const connection = requiredElement<HTMLElement>("#connection-state");
const updated = requiredElement<HTMLElement>("#last-updated");
const refreshButton = requiredElement<HTMLButtonElement>("#refresh-button");
const notice = requiredElement<HTMLElement>("#notice");
const noticeTitle = requiredElement<HTMLElement>("#notice-title");
const noticeMessage = requiredElement<HTMLElement>("#notice-message");
const signInLink = requiredElement<HTMLAnchorElement>("#sign-in-link");

const client = createAdminClient();
let selected: AdminSection = "state";
let selectedResource: string | null = null;
let resources: AdminResource[] = [];
let writeCapabilities: AdminWriteCapability[] = [];
let busy = false;

function setConnection(state: "connecting" | "connected" | "error", label: string): void {
  connection.dataset["state"] = state;
  connection.textContent = label;
}

function showNotice(error: unknown): void {
  notice.hidden = false;
  signInLink.hidden = true;
  if (error instanceof AdminClientError) {
    noticeTitle.textContent = error.status === 401 ? "Authentication required" : "Admin request failed";
    noticeMessage.textContent = error.message;
    signInLink.hidden = error.status !== 401;
    setConnection("error", error.status === 401 ? "Authentication required" : "Unavailable");
    return;
  }
  noticeTitle.textContent = "Unable to load Admin data";
  noticeMessage.textContent = "The response could not be displayed. Try refreshing the section.";
  setConnection("error", "Unavailable");
}

function hideNotice(): void {
  notice.hidden = true;
  signInLink.hidden = true;
}

function jsonWriteForm(
  summaryText: string,
  fields: string[],
  submitLabel: string,
  submit: (values: unknown) => Promise<void>,
): HTMLDetailsElement {
  const details = document.createElement("details");
  details.className = "resource-write-details";
  const summary = document.createElement("summary");
  summary.textContent = summaryText;
  const form = document.createElement("form");
  form.className = "resource-write-form";
  const description = document.createElement("p");
  description.textContent = `Allowed fields: ${fields.join(", ")}. Enter a JSON object containing only fields you want to set.`;
  const label = document.createElement("label");
  label.textContent = "JSON values";
  const editor = document.createElement("textarea");
  editor.rows = 8;
  editor.maxLength = 1_048_576;
  editor.required = true;
  editor.spellcheck = false;
  editor.autocomplete = "off";
  editor.value = "{}";
  label.append(editor);
  const error = document.createElement("p");
  error.className = "form-error";
  error.hidden = true;
  error.setAttribute("role", "alert");
  const submitButton = document.createElement("button");
  submitButton.type = "submit";
  submitButton.className = "button button-secondary";
  submitButton.textContent = submitLabel;
  form.append(description, label, error, submitButton);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    error.hidden = true;
    let values: unknown;
    try {
      values = JSON.parse(editor.value);
    } catch {
      error.textContent = "Enter valid JSON before submitting.";
      error.hidden = false;
      return;
    }
    void submit(values);
  });
  details.append(summary, form);
  return details;
}

function resourceKeyValue(value: unknown): value is string | number {
  if (typeof value === "number") return Number.isFinite(value);
  return typeof value === "string" && value.length > 0 && value.length <= 255 &&
    value !== "." && value !== ".." && !/[\/?#\\\u0000-\u001f\u007f]/.test(value);
}

async function performResourceMutation(
  resourceName: string,
  successMessage: string,
  operation: (csrfToken: string) => Promise<unknown>,
): Promise<void> {
  if (busy) return;
  busy = true;
  refreshButton.disabled = true;
  setConnection("connecting", "Saving");
  let succeeded = false;
  try {
    const token = await client.csrfToken();
    await operation(token);
    succeeded = true;
    hideNotice();
  } catch (error) {
    showNotice(error);
  } finally {
    busy = false;
    refreshButton.disabled = false;
  }
  if (!succeeded) return;
  await loadResource(resourceName);
  const status = document.createElement("p");
  status.className = "resource-count";
  status.setAttribute("role", "status");
  status.textContent = successMessage;
  resourceTableView.append(status);
}

async function loadSection(section: AdminSection): Promise<void> {
  if (busy) return;
  busy = true;
  selected = section;
  selectedResource = null;
  refreshButton.disabled = true;
  dataView.hidden = false;
  resourceTableView.hidden = true;
  accessMode.textContent = "READ ONLY";
  setConnection("connecting", "Refreshing");
  const definition = ADMIN_SECTIONS[section];
  title.textContent = definition.label;
  dataTitle.textContent = definition.label;
  description.textContent = "Current values reported by Orbit Core.";
  for (const button of navigation.querySelectorAll<HTMLButtonElement>("button[data-section]")) {
    if (button.dataset["section"] === section) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  for (const button of resourceNavigation.querySelectorAll<HTMLButtonElement>("button[data-resource]")) {
    button.removeAttribute("aria-current");
  }
  try {
    const result = await client.read(section);
    dataView.textContent = JSON.stringify(result, null, 2) ?? "null";
    updated.textContent = `Updated ${new Intl.DateTimeFormat(undefined, {
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    }).format(new Date())}`;
    setConnection("connected", "Connected");
    hideNotice();
  } catch (error) {
    showNotice(error);
  } finally {
    busy = false;
    refreshButton.disabled = false;
  }
}

function resourceLabel(name: string): string {
  return name.split("-").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}

function displayValue(value: unknown): string {
  let rendered: string;
  if (value === null || value === undefined) rendered = "—";
  else if (typeof value === "string") rendered = value;
  else if (typeof value === "number" || typeof value === "boolean") rendered = String(value);
  else rendered = JSON.stringify(value) ?? "";
  return rendered.length > 2_000 ? `${rendered.slice(0, 2_000)}…` : rendered;
}

function renderResourceRows(
  resource: AdminResource,
  rows: AdminResourceRow[],
  capability?: AdminWriteCapability,
): void {
  resourceTableView.replaceChildren();
  if (capability !== undefined && capability.create_fields.length > 0) {
    resourceTableView.append(jsonWriteForm(
      "Create record",
      capability.create_fields,
      "Create",
      async (values) => performResourceMutation(
        resource.name,
        "Record created.",
        (token) => client.createResource(resource.name, capability.create_fields, token, values),
      ),
    ));
  }
  const editFormHost = document.createElement("div");
  editFormHost.className = "resource-edit-host";
  resourceTableView.append(editFormHost);
  const columns = new Set(resource.read_fields.slice(0, 64));
  for (const row of rows) {
    for (const field of Object.keys(row).sort()) {
      if (/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(field) && columns.size < 64) columns.add(field);
    }
  }
  const fieldNames = [...columns];
  const hasActions = capability !== undefined && rows.some((row) =>
    resourceKeyValue(row[capability.key_field]) &&
    (capability.update_fields.length > 0 || capability.allow_delete)
  );
  if (fieldNames.length === 0) {
    const empty = document.createElement("p");
    empty.className = "resource-empty-state";
    empty.textContent = "No readable fields are configured for this resource.";
    resourceTableView.append(empty);
    return;
  }
  if (rows.length === 0) {
    const empty = document.createElement("p");
    empty.className = "resource-empty-state";
    empty.textContent = "No records were returned for this resource.";
    resourceTableView.append(empty);
    return;
  }

  const wrapper = document.createElement("div");
  wrapper.className = "table-scroll";
  const table = document.createElement("table");
  table.className = "resource-table";
  const caption = document.createElement("caption");
  caption.textContent = `${resourceLabel(resource.name)} records`;
  const head = document.createElement("thead");
  const headerRow = document.createElement("tr");
  for (const field of fieldNames) {
    const cell = document.createElement("th");
    cell.scope = "col";
    cell.textContent = field;
    headerRow.append(cell);
  }
  if (hasActions) {
    const actionsHeader = document.createElement("th");
    actionsHeader.scope = "col";
    actionsHeader.textContent = "Actions";
    headerRow.append(actionsHeader);
  }
  head.append(headerRow);
  const body = document.createElement("tbody");
  for (const row of rows) {
    const tableRow = document.createElement("tr");
    for (const field of fieldNames) {
      const cell = document.createElement("td");
      cell.textContent = displayValue(row[field]);
      tableRow.append(cell);
    }
    const key = capability === undefined ? undefined : row[capability.key_field];
    if (hasActions) {
      const actions = document.createElement("td");
      if (capability !== undefined && resourceKeyValue(key)) {
        if (capability.update_fields.length > 0) {
          const edit = document.createElement("button");
          edit.type = "button";
          edit.className = "button button-secondary row-action";
          edit.textContent = "Edit";
          edit.addEventListener("click", () => {
            editFormHost.replaceChildren(jsonWriteForm(
              `Update ${resourceLabel(resource.name)} record`,
              capability.update_fields,
              "Save changes",
              async (values) => performResourceMutation(
                resource.name,
                "Record updated.",
                (token) => client.updateResource(
                  resource.name,
                  key,
                  capability.update_fields,
                  token,
                  values,
                ),
              ),
            ));
            editFormHost.firstElementChild?.scrollIntoView({ block: "nearest" });
          });
          actions.append(edit);
        }
        if (capability.allow_delete) {
          const remove = document.createElement("button");
          remove.type = "button";
          remove.className = "button button-secondary row-action";
          remove.textContent = "Delete";
          remove.addEventListener("click", () => {
            if (!globalThis.confirm("Delete this resource record? This action cannot be undone.")) return;
            void performResourceMutation(
              resource.name,
              "Record deleted.",
              (token) => client.deleteResource(resource.name, key, token),
            );
          });
          actions.append(remove);
        }
      }
      tableRow.append(actions);
    }
    body.append(tableRow);
  }
  table.append(caption, head, body);
  wrapper.append(table);
  resourceTableView.append(wrapper);
  const count = document.createElement("p");
  count.className = "resource-count";
  count.textContent = `Showing ${rows.length} ${rows.length === 1 ? "record" : "records"} (maximum 100 per request).`;
  resourceTableView.append(count);
}

async function loadResource(name: string): Promise<void> {
  if (busy) return;
  const resource = resources.find((item) => item.name === name);
  if (resource === undefined) return;
  busy = true;
  selectedResource = name;
  refreshButton.disabled = true;
  dataView.hidden = true;
  resourceTableView.hidden = false;
  resourceTableView.replaceChildren();
  setConnection("connecting", "Refreshing");
  const label = resourceLabel(name);
  const capability = writeCapabilities.find((item) => item.name === name);
  title.textContent = label;
  dataTitle.textContent = label;
  accessMode.textContent = capability === undefined ? "READ ONLY" : "RBAC + CSRF";
  description.textContent = "Fields and rows are limited by the authenticated server-side resource policy.";
  for (const button of navigation.querySelectorAll<HTMLButtonElement>("button[data-section]")) {
    button.removeAttribute("aria-current");
  }
  for (const button of resourceNavigation.querySelectorAll<HTMLButtonElement>("button[data-resource]")) {
    if (button.dataset["resource"] === name) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  try {
    renderResourceRows(resource, await client.readResource(name), capability);
    updated.textContent = `Updated ${new Intl.DateTimeFormat(undefined, {
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    }).format(new Date())}`;
    setConnection("connected", "Connected");
    hideNotice();
  } catch (error) {
    showNotice(error);
  } finally {
    busy = false;
    refreshButton.disabled = false;
  }
}

async function loadResourceCatalog(): Promise<void> {
  try {
    resources = await client.listResources();
    try {
      writeCapabilities = await client.listWriteCapabilities();
    } catch {
      writeCapabilities = [];
    }
    resourceNavigation.replaceChildren();
    for (const resource of resources) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "section-button";
      button.dataset["resource"] = resource.name;
      const icon = document.createElement("span");
      icon.className = "section-icon";
      icon.setAttribute("aria-hidden", "true");
      icon.textContent = "▤";
      const label = document.createElement("span");
      label.textContent = resourceLabel(resource.name);
      button.append(icon, label);
      button.addEventListener("click", () => void loadResource(resource.name));
      resourceNavigation.append(button);
    }
    resourceEmpty.textContent = resources.length === 0
      ? "No resources are configured for Admin."
      : "Choose a resource to inspect its first page.";
  } catch (error) {
    resourceNavigation.replaceChildren();
    resourceEmpty.textContent = error instanceof AdminClientError && error.status === 403
      ? "Your account cannot list Admin resources."
      : "Configured Admin resources are unavailable.";
  }
}

for (const [key, definition] of Object.entries(ADMIN_SECTIONS)) {
  const section = key as AdminSection;
  const button = document.createElement("button");
  button.type = "button";
  button.className = "section-button";
  button.dataset["section"] = section;
  button.setAttribute("aria-current", section === selected ? "page" : "false");
  const icon = document.createElement("span");
  icon.className = "section-icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = definition.icon;
  const label = document.createElement("span");
  label.textContent = definition.label;
  button.append(icon, label);
  button.addEventListener("click", () => void loadSection(section));
  navigation.append(button);
}

refreshButton.addEventListener("click", () => {
  if (selectedResource !== null) void loadResource(selectedResource);
  else void loadSection(selected);
});
void loadSection(selected);
void loadResourceCatalog();
