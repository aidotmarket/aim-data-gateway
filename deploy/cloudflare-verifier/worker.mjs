// node_modules/@cloudflare/containers/dist/lib/helpers.js
function generateId(length = 9) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += alphabet[bytes[i] % alphabet.length];
  }
  return result;
}
function parseTimeExpression(timeExpression) {
  if (typeof timeExpression === "number") {
    return timeExpression;
  }
  if (typeof timeExpression === "string") {
    const match = timeExpression.match(/^(\d+)([smh])$/);
    if (!match) {
      throw new Error(`invalid time expression ${timeExpression}`);
    }
    const value = parseInt(match[1]);
    const unit = match[2];
    switch (unit) {
      case "s":
        return value;
      case "m":
        return value * 60;
      case "h":
        return value * 60 * 60;
      default:
        throw new Error(`unknown time unit ${unit}`);
    }
  }
  throw new Error(`invalid type for a time expression: ${typeof timeExpression}`);
}

// node_modules/@cloudflare/containers/dist/lib/container.js
import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
var NO_CONTAINER_INSTANCE_ERROR = "there is no container instance that can be provided to this durable object";
var RATE_LIMITED_ERROR = "you are requesting too many containers per second";
var RUNTIME_SIGNALLED_ERROR = "runtime signalled the container to exit:";
var UNEXPECTED_EXIT_ERROR = "container exited with unexpected exit code:";
var NOT_LISTENING_ERROR = "the container is not listening";
var CONTAINER_STATE_KEY = "__CF_CONTAINER_STATE";
var OUTBOUND_CONFIGURATION_KEY = "OUTBOUND_CONFIGURATION";
var MAX_ALARM_RETRIES = 3;
var PING_TIMEOUT_MS = 5e3;
var DEFAULT_SLEEP_AFTER = "10m";
var INSTANCE_POLL_INTERVAL_MS = 300;
var TIMEOUT_TO_GET_CONTAINER_MS = 8e3;
var TIMEOUT_TO_GET_PORTS_MS = 2e4;
var FALLBACK_PORT_TO_CHECK = 33;
var outboundHandlersRegistry = /* @__PURE__ */ new Map();
var defaultOutboundHandlerNameRegistry = /* @__PURE__ */ new Map();
var outboundByHostRegistry = /* @__PURE__ */ new Map();
var signalToNumbers = {
  SIGINT: 2,
  SIGTERM: 15,
  SIGKILL: 9
};
function isErrorOfType(e, matchingString) {
  const errorString = e instanceof Error ? e.message : String(e);
  return errorString.toLowerCase().includes(matchingString);
}
var isNoInstanceError = (error) => isErrorOfType(error, NO_CONTAINER_INSTANCE_ERROR);
var isRateLimitedError = (error) => isErrorOfType(error, RATE_LIMITED_ERROR);
var isRuntimeSignalledError = (error) => isErrorOfType(error, RUNTIME_SIGNALLED_ERROR);
var isNotListeningError = (error) => isErrorOfType(error, NOT_LISTENING_ERROR);
var isContainerExitNonZeroError = (error) => isErrorOfType(error, UNEXPECTED_EXIT_ERROR);
function getExitCodeFromError(error) {
  if (!(error instanceof Error)) {
    return null;
  }
  if (isRuntimeSignalledError(error)) {
    return +error.message.toLowerCase().slice(error.message.toLowerCase().indexOf(RUNTIME_SIGNALLED_ERROR) + RUNTIME_SIGNALLED_ERROR.length + 1);
  }
  if (isContainerExitNonZeroError(error)) {
    return +error.message.toLowerCase().slice(error.message.toLowerCase().indexOf(UNEXPECTED_EXIT_ERROR) + UNEXPECTED_EXIT_ERROR.length + 1);
  }
  return null;
}
function addTimeoutSignal(existingSignal, timeoutMs) {
  const controller = new AbortController();
  if (existingSignal?.aborted) {
    controller.abort();
    return controller.signal;
  }
  existingSignal?.addEventListener("abort", () => controller.abort());
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  controller.signal.addEventListener("abort", () => clearTimeout(timeoutId));
  return controller.signal;
}
function simpleGlobMatch(pattern, value) {
  const parts = pattern.split("*");
  if (parts.length === 1)
    return pattern === value;
  if (!value.startsWith(parts[0]))
    return false;
  if (!value.endsWith(parts[parts.length - 1]))
    return false;
  let pos = parts[0].length;
  for (let i = 1; i < parts.length - 1; i++) {
    const idx = value.indexOf(parts[i], pos);
    if (idx === -1)
      return false;
    pos = idx + parts[i].length;
  }
  return pos <= value.length - parts[parts.length - 1].length;
}
function matchesHostList(hostname, patterns) {
  return patterns.some((pattern) => simpleGlobMatch(pattern, hostname));
}
function normalizeHostname(hostname) {
  let end = hostname.length;
  while (end > 0 && hostname[end - 1] === ".") {
    end--;
  }
  return hostname.slice(0, end);
}
var ContainerState = class {
  storage;
  status;
  constructor(storage) {
    this.storage = storage;
  }
  async setRunning() {
    await this.setStatusAndupdate("running");
  }
  async setHealthy() {
    await this.setStatusAndupdate("healthy");
  }
  async setStopping() {
    await this.setStatusAndupdate("stopping");
  }
  async setStopped() {
    await this.setStatusAndupdate("stopped");
  }
  async setStoppedIfUnchanged(previousState) {
    if (this.status !== previousState) {
      return;
    }
    await this.setStopped();
  }
  async setStoppedWithCode(exitCode) {
    this.status = { status: "stopped_with_code", lastChange: Date.now(), exitCode };
    await this.update();
  }
  async getState() {
    if (!this.status) {
      const state = await this.storage.get(CONTAINER_STATE_KEY);
      if (!state) {
        this.status = {
          status: "stopped",
          lastChange: Date.now()
        };
        await this.update();
      } else {
        this.status = state;
      }
    }
    return this.status;
  }
  async setStatusAndupdate(status) {
    this.status = { status, lastChange: Date.now() };
    await this.update();
  }
  async update() {
    if (!this.status)
      throw new Error("status should be init");
    await this.storage.put(CONTAINER_STATE_KEY, this.status);
  }
};
var ContainerProxy = class extends WorkerEntrypoint {
  async fetch(request) {
    const url = new URL(request.url);
    const hostname = normalizeHostname(url.hostname);
    const { className, containerId, outboundByHostOverrides, outboundHandlerOverride, enableInternet, allowedHosts, deniedHosts, interceptAll } = this.ctx.props;
    const baseCtx = { containerId, className };
    if (deniedHosts && matchesHostList(hostname, deniedHosts)) {
      return new Response("Origin is disallowed", { status: 520 });
    }
    if (allowedHosts && !matchesHostList(hostname, allowedHosts)) {
      return new Response("Origin is disallowed", { status: 520 });
    }
    const handlers = outboundHandlersRegistry.get(className);
    if (outboundByHostOverrides && handlers) {
      const override = outboundByHostOverrides[hostname] ?? Object.entries(outboundByHostOverrides).find(([pattern]) => pattern !== hostname && simpleGlobMatch(pattern, hostname))?.[1];
      if (override && handlers[override.method]) {
        return handlers[override.method](request, this.env, {
          ...baseCtx,
          params: override.params
        });
      }
    }
    const handlersByHost = outboundByHostRegistry.get(className);
    if (handlersByHost) {
      const handler = handlersByHost[hostname] ?? Object.entries(handlersByHost).find(([pattern]) => pattern !== hostname && simpleGlobMatch(pattern, hostname))?.[1];
      if (handler) {
        return handler(request, this.env, baseCtx);
      }
    }
    if (!interceptAll) {
      if (allowedHosts || enableInternet) {
        return fetch(request);
      }
      return new Response("Origin is disallowed", { status: 520 });
    }
    if (outboundHandlerOverride && handlers?.[outboundHandlerOverride.method]) {
      return handlers[outboundHandlerOverride.method](request, this.env, {
        ...baseCtx,
        params: outboundHandlerOverride.params
      });
    }
    const defaultOutboundHandlerName = defaultOutboundHandlerNameRegistry.get(className);
    if (defaultOutboundHandlerName && handlers?.[defaultOutboundHandlerName]) {
      return handlers[defaultOutboundHandlerName](request, this.env, baseCtx);
    }
    if (allowedHosts) {
      return fetch(request);
    }
    if (enableInternet) {
      return fetch(request);
    }
    return new Response("Origin is disallowed", { status: 520 });
  }
};
var Container = class extends DurableObject {
  static get outboundByHost() {
    return outboundByHostRegistry.get(this.name);
  }
  static set outboundByHost(handlers) {
    outboundByHostRegistry.set(this.name, handlers);
  }
  static get outboundHandlers() {
    return outboundHandlersRegistry.get(this.name);
  }
  static set outboundHandlers(handlers) {
    const existing = outboundHandlersRegistry.get(this.name) ?? {};
    outboundHandlersRegistry.set(this.name, { ...existing, ...handlers });
  }
  static get outbound() {
    const handlerName = defaultOutboundHandlerNameRegistry.get(this.name);
    if (!handlerName)
      return void 0;
    return outboundHandlersRegistry.get(this.name)?.[handlerName];
  }
  static set outbound(handler) {
    const key = "__outbound__";
    const existing = outboundHandlersRegistry.get(this.name) ?? {};
    outboundHandlersRegistry.set(this.name, { ...existing, [key]: handler });
    defaultOutboundHandlerNameRegistry.set(this.name, key);
  }
  static get outboundProxies() {
    return this.outboundHandlers;
  }
  static set outboundProxies(handlers) {
    this.outboundHandlers = handlers;
  }
  static get outboundProxy() {
    return this.outbound;
  }
  static set outboundProxy(handler) {
    this.outbound = handler;
  }
  // =========================
  //     Public Attributes
  // =========================
  // Default port for the container (undefined means no default port)
  defaultPort;
  // Required ports that should be checked for availability during container startup
  // Override this in your subclass to specify ports that must be ready
  requiredPorts;
  // Timeout after which the container will sleep if no activity
  // The signal sent to the container by default is a SIGTERM.
  // The container won't get a SIGKILL if this threshold is triggered.
  sleepAfter = DEFAULT_SLEEP_AFTER;
  // Container configuration properties
  // Set these properties directly in your container instance
  envVars = {};
  entrypoint;
  enableInternet = true;
  labels = {};
  // When true, outbound HTTPS traffic from the container will be intercepted.
  // The container must trust /etc/cloudflare/certs/cloudflare-containers-ca.crt
  interceptHttps = false;
  // Hosts that are allowed to access the internet, even when enableInternet is false.
  // Useful for allowing specific domains on a per-host basis.
  allowedHosts;
  // Hosts that are denied internet access, even when enableInternet is true.
  // Also blocks hosts from being handled by the catch-all outbound handler.
  deniedHosts;
  // pingEndpoint is the host and path value that the class will use to send a request to the container and check if the
  // instance is ready.
  //
  // The user does not have to implement this route by any means,
  // but it's still useful if you want to control the path that
  // the Container class uses to send HTTP requests to.
  pingEndpoint = "ping";
  applyOutboundInterceptionPromise = Promise.resolve();
  usingInterception = false;
  // =========================
  //     PUBLIC INTERFACE
  // =========================
  constructor(ctx, env, options) {
    super(ctx, env);
    if (ctx.container === void 0) {
      throw new Error("Containers have not been enabled for this Durable Object class. Have you correctly setup your Wrangler config? More info: https://developers.cloudflare.com/containers/get-started/#configuration");
    }
    this.state = new ContainerState(this.ctx.storage);
    const persistedOutboundConfiguration = this.restoreOutboundConfiguration();
    this.ctx.blockConcurrencyWhile(async () => {
      await this.scheduleNextAlarm();
      this.renewActivityTimeout();
      const ctor = this.constructor;
      if (persistedOutboundConfiguration !== void 0 || ctor.outboundByHost !== void 0 || ctor.outbound !== void 0 || ctor.outboundHandlers !== void 0 || this.effectiveAllowedHosts !== void 0 || this.effectiveDeniedHosts !== void 0) {
        this.usingInterception = true;
      }
      if (this.container.running) {
        this.applyOutboundInterceptionPromise = this.applyOutboundInterception();
      }
    });
    this.container = ctx.container;
    if (options) {
      if (options.defaultPort !== void 0)
        this.defaultPort = options.defaultPort;
      if (options.sleepAfter !== void 0)
        this.sleepAfter = options.sleepAfter;
      if (options.envVars !== void 0)
        this.envVars = options.envVars;
      if (options.entrypoint !== void 0)
        this.entrypoint = options.entrypoint;
      if (options.enableInternet !== void 0)
        this.enableInternet = options.enableInternet;
    }
    this.sql`
      CREATE TABLE IF NOT EXISTS container_schedules (
        id TEXT PRIMARY KEY NOT NULL DEFAULT (randomblob(9)),
        callback TEXT NOT NULL,
        payload TEXT,
        type TEXT NOT NULL CHECK(type IN ('scheduled', 'delayed')),
        time INTEGER NOT NULL,
        delayInSeconds INTEGER,
        created_at INTEGER DEFAULT (unixepoch())
      )
    `;
    if (this.container.running) {
      this.monitor = this.container.monitor();
      this.setupMonitorCallbacks();
    }
  }
  /**
   * Gets the current state of the container
   * @returns Promise<State>
   */
  async getState() {
    return { ...await this.state.getState() };
  }
  // ====================================
  //     OUTBOUND INTERCEPTION CONFIG
  // ====================================
  /**
   * Set the catch-all outbound handler to a named method from `outboundHandlers`.
   * Overrides the default `outbound` at runtime via ContainerProxy props.
   *
   * @param methodName - Name of a method defined in `static outboundHandlers`
   * @param params - Optional params passed to the handler as `ctx.params`
   * @throws Error if the method name is not found in `outboundHandlers`
   */
  async setOutboundHandler(methodName, ...paramsArg) {
    this.validateOutboundHandlerMethodName(methodName);
    this.outboundHandlerOverride = paramsArg.length === 0 ? { method: methodName } : { method: methodName, params: paramsArg[0] };
    await this.refreshOutboundInterception();
  }
  /**
   * Add or override a hostname-specific outbound handler at runtime,
   * referencing a named method from `outboundHandlers`.
   * Overrides any matching entry in `static outboundByHost` for this hostname.
   *
   * @param hostname - The hostname or ip:port to intercept (e.g. `'google.com'`)
   * @param methodName - Name of a method defined in `static outboundHandlers`
   * @param params - Optional params passed to the handler as `ctx.params`
   * @throws Error if the method name is not found in `outboundHandlers`
   */
  async setOutboundByHost(hostname, methodName, ...paramsArg) {
    this.validateOutboundHandlerMethodName(methodName);
    this.outboundByHostOverrides[hostname] = paramsArg.length === 0 ? { method: methodName } : { method: methodName, params: paramsArg[0] };
    await this.refreshOutboundInterception();
  }
  /**
   * Remove a runtime hostname override added via `setOutboundByHost`.
   * The default handler from `static outboundByHost` (if any) will be used again.
   *
   * @param hostname - The hostname or ip:port to stop overriding
   */
  async removeOutboundByHost(hostname) {
    delete this.outboundByHostOverrides[hostname];
    await this.refreshOutboundInterception();
  }
  /**
   * Replace all runtime hostname overrides at once.
   * Each value may be either a method name or an object with `method` and `params`.
   *
   * @param handlers - Record mapping hostnames to handler configs in `outboundHandlers`
   * @throws Error if any method name is not found in `outboundHandlers`
   */
  async setOutboundByHosts(handlers) {
    for (const handler of Object.values(handlers)) {
      const methodName = typeof handler === "string" ? handler : handler.method;
      this.validateOutboundHandlerMethodName(methodName);
    }
    this.outboundByHostOverrides = Object.fromEntries(Object.entries(handlers).map(([hostname, handler]) => [
      hostname,
      typeof handler === "string" ? { method: handler } : handler
    ]));
    await this.refreshOutboundInterception();
  }
  // ====================================
  //     ALLOWED / DENIED HOSTS CONFIG
  // ====================================
  /**
   * Replace all allowed hosts at runtime.
   * Allowed hosts get internet access even when `enableInternet` is false.
   *
   * @param hosts - Array of hostnames to allow (e.g. `['api.stripe.com', 'example.com']`)
   */
  async setAllowedHosts(hosts) {
    this.allowedHostsOverride = [...hosts];
    this.usingInterception = true;
    await this.refreshOutboundInterception();
  }
  /**
   * Replace all denied hosts at runtime.
   * Denied hosts are blocked unconditionally, even when `enableInternet` is true
   * or a catch-all outbound handler is set.
   *
   * @param hosts - Array of hostnames to deny (e.g. `['evil.com', 'blocked.org']`)
   */
  async setDeniedHosts(hosts) {
    this.deniedHostsOverride = [...hosts];
    this.usingInterception = true;
    await this.refreshOutboundInterception();
  }
  /**
   * Add a single hostname to the allowed hosts list at runtime.
   *
   * @param hostname - The hostname to allow (e.g. `'api.stripe.com'`)
   */
  async allowHost(hostname) {
    const effective = this.effectiveAllowedHosts ?? [];
    if (!effective.includes(hostname)) {
      this.allowedHostsOverride = [...effective, hostname];
    }
    this.usingInterception = true;
    await this.refreshOutboundInterception();
  }
  /**
   * Add a single hostname to the denied hosts list at runtime.
   *
   * @param hostname - The hostname to deny (e.g. `'evil.com'`)
   */
  async denyHost(hostname) {
    const effective = this.effectiveDeniedHosts ?? [];
    if (!effective.includes(hostname)) {
      this.deniedHostsOverride = [...effective, hostname];
    }
    this.usingInterception = true;
    await this.refreshOutboundInterception();
  }
  /**
   * Remove a hostname from the allowed hosts list.
   *
   * @param hostname - The hostname to remove from the allow list
   */
  async removeAllowedHost(hostname) {
    this.allowedHostsOverride = (this.effectiveAllowedHosts ?? []).filter((h) => h !== hostname);
    await this.refreshOutboundInterception();
  }
  /**
   * Remove a hostname from the denied hosts list.
   *
   * @param hostname - The hostname to remove from the deny list
   */
  async removeDeniedHost(hostname) {
    this.deniedHostsOverride = (this.effectiveDeniedHosts ?? []).filter((h) => h !== hostname);
    await this.refreshOutboundInterception();
  }
  // ==========================
  //     CONTAINER STARTING
  // ==========================
  /**
   * Start the container if it's not running and set up monitoring and lifecycle hooks,
   * without waiting for ports to be ready.
   *
   * It will automatically retry if the container fails to start, using the specified waitOptions
   *
   *
   * @example
   * await this.start({
   *   envVars: { DEBUG: 'true', NODE_ENV: 'development' },
   *   entrypoint: ['npm', 'run', 'dev'],
   *   enableInternet: false,
   *   labels: { tenant: 'acme', env: 'prod' },
   * });
   *
   * @param startOptions - Override `envVars`, `entrypoint`, `enableInternet` and `labels` on a per-instance basis
   * @param waitOptions - Optional wait configuration with abort signal for cancellation. Default ~8s timeout.
   * @returns A promise that resolves when the container start command has been issued
   * @throws Error if no container context is available or if all start attempts fail
   */
  async start(startOptions, waitOptions) {
    const portToCheck = waitOptions?.portToCheck ?? this.defaultPort ?? (this.requiredPorts ? this.requiredPorts[0] : FALLBACK_PORT_TO_CHECK);
    const pollInterval = waitOptions?.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
    await this.startContainerIfNotRunning({
      signal: waitOptions?.signal,
      waitInterval: pollInterval,
      retries: waitOptions?.retries ?? Math.ceil(TIMEOUT_TO_GET_CONTAINER_MS / pollInterval),
      portToCheck
    }, startOptions);
    this.setupMonitorCallbacks();
    await this.ctx.blockConcurrencyWhile(async () => {
      await this.onStart();
    });
  }
  async startAndWaitForPorts(portsOrArgs, cancellationOptions, startOptions) {
    let ports;
    let resolvedCancellationOptions;
    let resolvedStartOptions;
    if (typeof portsOrArgs === "object" && portsOrArgs !== null && !Array.isArray(portsOrArgs)) {
      ports = portsOrArgs.ports;
      resolvedCancellationOptions = portsOrArgs.cancellationOptions;
      resolvedStartOptions = portsOrArgs.startOptions;
    } else {
      ports = portsOrArgs;
      resolvedCancellationOptions = cancellationOptions;
      resolvedStartOptions = startOptions;
    }
    const portsToCheck = await this.getPortsToCheck(ports);
    await this.syncPendingStoppedEvents();
    resolvedCancellationOptions ??= {};
    const containerGetTimeout = resolvedCancellationOptions.instanceGetTimeoutMS ?? TIMEOUT_TO_GET_CONTAINER_MS;
    const pollInterval = resolvedCancellationOptions.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
    const containerGetRetries = Math.ceil(containerGetTimeout / pollInterval);
    const waitOptions = {
      signal: resolvedCancellationOptions.abort,
      retries: containerGetRetries,
      waitInterval: pollInterval,
      portToCheck: portsToCheck[0]
    };
    const triesUsed = await this.startContainerIfNotRunning(waitOptions, resolvedStartOptions);
    const totalPortReadyTries = Math.ceil((resolvedCancellationOptions.portReadyTimeoutMS ?? TIMEOUT_TO_GET_PORTS_MS) / pollInterval);
    let triesLeft = totalPortReadyTries - triesUsed;
    for (const port of portsToCheck) {
      triesLeft = await this.waitForPort({
        signal: resolvedCancellationOptions.abort,
        waitInterval: pollInterval,
        retries: triesLeft,
        portToCheck: port
      });
    }
    this.setupMonitorCallbacks();
    await this.ctx.blockConcurrencyWhile(async () => {
      await this.state.setHealthy();
      await this.onStart();
    });
  }
  /**
   *
   * Waits for a specified port to be ready
   *
   * Returns the number of tries used to get the port, or throws if it couldn't get the port within the specified retry limits.
   *
   * @param waitOptions -
   * - `portToCheck`: The port number to check
   * - `abort`: Optional AbortSignal to cancel waiting
   * - `retries`: Number of retries before giving up (default: TRIES_TO_GET_PORTS)
   * - `waitInterval`: Interval between retries in milliseconds (default: INSTANCE_POLL_INTERVAL_MS)
   */
  async waitForPort(waitOptions) {
    const port = waitOptions.portToCheck;
    const tcpPort = this.container.getTcpPort(port);
    const abortedSignal = new Promise((res) => {
      waitOptions.signal?.addEventListener("abort", () => {
        res(true);
      });
    });
    const pollInterval = waitOptions.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
    const tries = waitOptions.retries ?? Math.ceil(TIMEOUT_TO_GET_PORTS_MS / pollInterval);
    for (let i = 0; i < tries; i++) {
      try {
        const combinedSignal = addTimeoutSignal(waitOptions.signal, PING_TIMEOUT_MS);
        await tcpPort.fetch(`http://${this.pingEndpoint}`, { signal: combinedSignal });
        break;
      } catch (e) {
        const errorMessage = e instanceof Error ? e.message : String(e);
        if (!this.container.running) {
          try {
            await this.onError(new Error(`Container crashed while checking for ports, did you start the container and setup the entrypoint correctly?`));
          } catch {
          }
          throw e;
        }
        if (i === tries - 1) {
          try {
            await this.onError(`Failed to verify port ${port} is available after ${(i + 1) * pollInterval}ms, last error: ${errorMessage}`);
          } catch {
          }
          throw e;
        }
        await Promise.any([
          new Promise((resolve) => setTimeout(resolve, pollInterval)),
          abortedSignal
        ]);
        if (waitOptions.signal?.aborted) {
          throw new Error("Container request aborted.", { cause: e });
        }
      }
    }
    return tries;
  }
  // =======================
  //     LIFECYCLE HOOKS
  // =======================
  /**
   * Send a signal to the container.
   * @param signal - The signal to send to the container (default: 15 for SIGTERM)
   */
  async stop(signal = "SIGTERM") {
    if (this.container.running) {
      this.container.signal(typeof signal === "string" ? signalToNumbers[signal] : signal);
    }
    await this.syncPendingStoppedEvents();
  }
  /**
   * Destroys the container with a SIGKILL. Triggers onStop.
   */
  async destroy() {
    await this.container.destroy();
  }
  /**
   * Lifecycle method called when container starts successfully
   * Override this method in subclasses to handle container start events
   */
  onStart() {
  }
  /**
   * Lifecycle method called when container shuts down
   * Override this method in subclasses to handle Container stopped events
   * @param params - Object containing exitCode and reason for the stop
   */
  onStop(params) {
    void params;
  }
  /**
   * Lifecycle method called when the container is running, and the activity timeout
   * expiration (set by `sleepAfter`) has been reached.
   *
   * If you want to shutdown the container, you should call this.stop() here
   *
   * By default, this method calls `this.stop()`
   */
  async onActivityExpired() {
    console.log("Activity expired, signalling container to stop");
    if (!this.container.running) {
      return;
    }
    await this.stop();
  }
  /**
   * Error handler for container errors
   * Override this method in subclasses to handle container errors
   * @param error - The error that occurred
   * @returns Can return any value or throw the error
   */
  onError(error) {
    console.error("Container error:", error);
    throw error;
  }
  /**
   * Renew the container's activity timeout
   *
   * Call this method whenever there is activity on the container
   */
  renewActivityTimeout() {
    const timeoutInMs = parseTimeExpression(this.sleepAfter) * 1e3;
    this.sleepAfterMs = Date.now() + timeoutInMs;
  }
  /**
   * Decrement the inflight request counter.
   * When the counter transitions to 0, renew the activity timeout so the
   * inactivity window starts fresh from the moment the last request completes.
   */
  decrementInflight() {
    this.inflightRequests = Math.max(0, this.inflightRequests - 1);
    if (this.inflightRequests === 0) {
      this.renewActivityTimeout();
    }
  }
  // ==================
  //     SCHEDULING
  // ==================
  /**
   * Schedule a task to be executed in the future.
   *
   * We strongly recommend using this instead of the `alarm` handler.
   *
   * @template T Type of the payload data
   * @param when When to execute the task (Date object or number of seconds delay)
   * @param callback Name of the method to call
   * @param payload Data to pass to the callback
   * @returns Schedule object representing the scheduled task
   */
  async schedule(when, callback, payload) {
    const id = generateId(9);
    if (typeof callback !== "string") {
      throw new Error("Callback must be a string (method name)");
    }
    if (typeof this[callback] !== "function") {
      throw new Error(`this.${callback} is not a function`);
    }
    if (when instanceof Date) {
      const timestamp = Math.floor(when.getTime() / 1e3);
      this.sql`
        INSERT OR REPLACE INTO container_schedules (id, callback, payload, type, time)
        VALUES (${id}, ${callback}, ${JSON.stringify(payload)}, 'scheduled', ${timestamp})
      `;
      await this.scheduleNextAlarm();
      return {
        taskId: id,
        callback,
        payload,
        time: timestamp,
        type: "scheduled"
      };
    }
    if (typeof when === "number") {
      const time = Math.floor(Date.now() / 1e3 + when);
      this.sql`
        INSERT OR REPLACE INTO container_schedules (id, callback, payload, type, delayInSeconds, time)
        VALUES (${id}, ${callback}, ${JSON.stringify(payload)}, 'delayed', ${when}, ${time})
      `;
      await this.scheduleNextAlarm();
      return {
        taskId: id,
        callback,
        payload,
        delayInSeconds: when,
        time,
        type: "delayed"
      };
    }
    throw new Error("Invalid schedule type. 'when' must be a Date or number of seconds");
  }
  // ============
  //     HTTP
  // ============
  /**
   * Send a request to the container (HTTP or WebSocket) using standard fetch API signature
   *
   * This method handles HTTP requests to the container.
   *
   * WebSocket requests done outside the DO won't work until https://github.com/cloudflare/workerd/issues/2319 is addressed.
   * Until then, please use `switchPort` + `fetch()`.
   *
   * Method supports multiple signatures to match standard fetch API:
   * - containerFetch(request: Request, port?: number)
   * - containerFetch(url: string | URL, init?: RequestInit, port?: number)
   *
   * Starts the container if not already running, and waits for the target port to be ready.
   *
   * @returns A Response from the container
   */
  async containerFetch(requestOrUrl, portOrInit, portParam) {
    const { request, port } = this.requestAndPortFromContainerFetchArgs(requestOrUrl, portOrInit, portParam);
    const state = await this.state.getState();
    if (!this.container.running || state.status !== "healthy") {
      try {
        await this.startAndWaitForPorts(port, { abort: request.signal });
      } catch (e) {
        if (isNoInstanceError(e)) {
          return new Response("There is no Container instance available at this time.\nThis is likely because you have reached your max concurrent instance count (set in wrangler config) or are you currently provisioning the Container.\nIf you are deploying your Container for the first time, check your dashboard to see provisioning status, this may take a few minutes.", { status: 503 });
        }
        if (isRateLimitedError(e)) {
          return new Response(e instanceof Error ? e.message : String(e), { status: 429 });
        }
        return new Response(`Failed to start container: ${e instanceof Error ? e.message : String(e)}`, {
          status: 500
        });
      }
    }
    const tcpPort = this.container.getTcpPort(port);
    const containerUrl = request.url.replace("https:", "http:");
    this.inflightRequests++;
    try {
      this.renewActivityTimeout();
      const res = await tcpPort.fetch(containerUrl, request);
      if (res.webSocket !== null) {
        const containerWs = res.webSocket;
        const [client, server] = Object.values(new WebSocketPair());
        let settled = false;
        const settleInflight = () => {
          if (!settled) {
            settled = true;
            this.decrementInflight();
          }
        };
        containerWs.accept();
        server.accept();
        server.addEventListener("message", async (event) => {
          this.renewActivityTimeout();
          try {
            const data = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
            containerWs.send(data);
          } catch {
            server.close(1011, "Failed to forward message to container");
          }
        });
        containerWs.addEventListener("message", async (event) => {
          this.renewActivityTimeout();
          try {
            const data = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
            server.send(data);
          } catch {
            containerWs.close(1011, "Failed to forward message to client");
          }
        });
        server.addEventListener("close", (event) => {
          settleInflight();
          const code = event.code === 1005 || event.code === 1006 ? 1e3 : event.code;
          containerWs.close(code, event.reason);
        });
        containerWs.addEventListener("close", (event) => {
          settleInflight();
          const code = event.code === 1005 || event.code === 1006 ? 1e3 : event.code;
          server.close(code, event.reason);
        });
        server.addEventListener("error", () => {
          settleInflight();
          containerWs.close(1011, "Client WebSocket error");
        });
        containerWs.addEventListener("error", () => {
          settleInflight();
          server.close(1011, "Container WebSocket error");
        });
        return new Response(null, { status: res.status, webSocket: client, headers: res.headers });
      }
      if (res.body !== null) {
        const { readable, writable } = new IdentityTransformStream();
        res.body?.pipeTo(writable).finally(() => {
          this.decrementInflight();
        });
        return new Response(readable, res);
      }
      this.decrementInflight();
      return res;
    } catch (e) {
      this.decrementInflight();
      if (!(e instanceof Error)) {
        throw e;
      }
      if (e.message.includes("Network connection lost.")) {
        return new Response("Container suddenly disconnected, try again", { status: 500 });
      }
      console.error(`Error proxying request to container ${this.ctx.id}:`, e);
      return new Response(`Error proxying request to container: ${e instanceof Error ? e.message : String(e)}`, { status: 500 });
    }
  }
  /**
   *
   * Fetch handler on the Container class.
   * By default this forwards all requests to the container by calling `containerFetch`.
   * Use `switchPort` to specify which port on the container to target, or this will use `defaultPort`.
   * @param request The request to handle
   */
  async fetch(request) {
    if (this.defaultPort === void 0 && !request.headers.has("cf-container-target-port")) {
      throw new Error("No port configured for this container. Set the `defaultPort` in your Container subclass, or specify a port with `container.fetch(switchPort(request, port))`.");
    }
    let portValue = this.defaultPort;
    if (request.headers.has("cf-container-target-port")) {
      const portFromHeaders = parseInt(request.headers.get("cf-container-target-port") ?? "");
      if (isNaN(portFromHeaders)) {
        throw new Error("port value from switchPort is not a number");
      } else {
        portValue = portFromHeaders;
      }
    }
    return await this.containerFetch(request, portValue);
  }
  // ===============================
  // ===============================
  //     PRIVATE METHODS & ATTRS
  // ===============================
  // ===============================
  // ==========================
  //     PRIVATE ATTRIBUTES
  // ==========================
  container;
  // onStopCalled will be true when we are in the middle of an onStop call
  onStopCalled = false;
  state;
  monitor;
  // Coalesces concurrent calls to startContainerIfNotRunning so we never
  // call `this.container.start()` twice. Without this guard, two requests
  // racing the readiness path can both pass the `if (this.container.running)`
  // early-return (each yielding the DO input gate at storage awaits) and
  // both reach the synchronous workerd `start()`, causing the second to
  // throw "start() cannot be called on a container that is already running."
  // See https://github.com/cloudflare/containers/issues/173.
  startInFlight;
  monitoredPromise;
  sleepAfterMs = 0;
  inflightRequests = 0;
  // Outbound interception runtime overrides (passed through ContainerProxy props)
  outboundByHostOverrides = {};
  outboundHandlerOverride;
  // Only set when the user calls setAllowedHosts/setDeniedHosts at runtime
  allowedHostsOverride;
  deniedHostsOverride;
  // The runtime does not expose a way to remove outbound interceptions yet, so
  // once we promote an instance to intercept-all we must keep using it.
  hasInterceptAllRegistration = false;
  // ==========================
  //     GENERAL HELPERS
  // ==========================
  /**
   * Validates that a method name exists in the outboundHandlers registry for this class.
   * @throws Error if the method name is not found
   */
  validateOutboundHandlerMethodName(methodName) {
    const handlers = outboundHandlersRegistry.get(this.constructor.name);
    if (!handlers || !(methodName in handlers)) {
      throw new Error(`Outbound handler method '${methodName}' not found in outboundHandlers for ${this.constructor.name}`);
    }
  }
  get effectiveAllowedHosts() {
    return this.allowedHostsOverride ?? this.allowedHosts;
  }
  get effectiveDeniedHosts() {
    return this.deniedHostsOverride ?? this.deniedHosts;
  }
  getOutboundConfiguration() {
    return {
      outboundByHostOverrides: Object.keys(this.outboundByHostOverrides).length > 0 ? this.outboundByHostOverrides : void 0,
      outboundHandlerOverride: this.outboundHandlerOverride,
      allowedHosts: this.effectiveAllowedHosts,
      deniedHosts: this.effectiveDeniedHosts,
      hasInterceptAllRegistration: this.hasInterceptAllRegistration || void 0
    };
  }
  persistOutboundConfiguration(configuration) {
    this.ctx.storage.kv.put(OUTBOUND_CONFIGURATION_KEY, {
      ...configuration,
      allowedHosts: this.allowedHostsOverride,
      deniedHosts: this.deniedHostsOverride
    });
  }
  restoreOutboundConfiguration() {
    const configuration = this.ctx.storage.kv.get(OUTBOUND_CONFIGURATION_KEY);
    if (!configuration) {
      return void 0;
    }
    this.outboundHandlerOverride = void 0;
    if (configuration.outboundHandlerOverride !== void 0) {
      try {
        this.validateOutboundHandlerMethodName(configuration.outboundHandlerOverride.method);
        this.outboundHandlerOverride = configuration.outboundHandlerOverride;
      } catch (error) {
        console.warn("Ignoring invalid persisted outbound handler override:", error);
      }
    }
    this.outboundByHostOverrides = {};
    for (const [hostname, override] of Object.entries(configuration.outboundByHostOverrides ?? {})) {
      try {
        this.validateOutboundHandlerMethodName(override.method);
        this.outboundByHostOverrides[hostname] = override;
      } catch (error) {
        console.warn(`Ignoring invalid persisted outbound override for ${hostname}:`, error);
      }
    }
    this.hasInterceptAllRegistration = configuration.hasInterceptAllRegistration === true;
    if (configuration.allowedHosts) {
      this.allowedHostsOverride = configuration.allowedHosts;
    }
    if (configuration.deniedHosts) {
      this.deniedHostsOverride = configuration.deniedHosts;
    }
    return this.getOutboundConfiguration();
  }
  /**
   * Returns true if a catch-all outbound HTTP interception is needed.
   * This is the case when a static `outbound` handler or a runtime
   * `outboundHandlerOverride` (catch-all) is configured.
   * When false, we only intercept specific hosts to avoid overhead.
   */
  needsCatchAllInterception() {
    const ctor = this.constructor;
    return ctor.outbound !== void 0 || this.outboundHandlerOverride !== void 0;
  }
  hasMutableOutboundConfiguration() {
    return Object.keys(this.outboundByHostOverrides).length > 0 || this.allowedHostsOverride !== void 0 || this.deniedHostsOverride !== void 0;
  }
  shouldInterceptAllOutbound() {
    return this.hasInterceptAllRegistration || this.needsCatchAllInterception() || this.effectiveAllowedHosts !== void 0 || this.effectiveDeniedHosts !== void 0 || this.hasMutableOutboundConfiguration();
  }
  getStaticOutboundByHostKeys() {
    const ctor = this.constructor;
    return ctor.outboundByHost ? Object.keys(ctor.outboundByHost) : [];
  }
  /**
   * Collects all hostnames that need per-host outbound interception.
   * This path is only used for the narrow optimized case where outbound
   * handling is static and host-specific.
   */
  getHostsToIntercept() {
    const hosts = /* @__PURE__ */ new Set();
    const ctor = this.constructor;
    if (ctor.outboundByHost) {
      for (const hostname of Object.keys(ctor.outboundByHost)) {
        hosts.add(hostname);
      }
    }
    for (const hostname of Object.keys(this.outboundByHostOverrides)) {
      hosts.add(hostname);
    }
    return [...hosts];
  }
  async refreshOutboundInterception() {
    if (!this.usingInterception) {
      return;
    }
    this.applyOutboundInterceptionPromise = this.applyOutboundInterception();
    await this.applyOutboundInterceptionPromise;
  }
  /**
   * Applies (or re-applies) outbound HTTP interception with the current
   * default registries + runtime overrides passed through ContainerProxy props.
   *
   * Uses per-host interception only for static host-specific outbound handlers.
   * As soon as the config needs to evaluate all hosts (catch-all outbound,
   * allow/deny lists, or runtime-mutated outbound config), we promote the
   * container to intercept-all and keep it there until the instance restarts.
   *
   * When `interceptHttps` is enabled, also applies HTTPS interception:
   * - Intercept-all mode: `interceptOutboundHttps('*', ...)` for all HTTPS traffic
   * - Per-host mode: `interceptOutboundHttps(host, ...)` for each known host
   */
  async applyOutboundInterception() {
    const ctx = this.ctx;
    if (ctx.exports === void 0) {
      throw new Error("ctx.exports is undefined, please try to update your compatibility date or export ContainerProxy from the containers package in your worker entrypoint");
    }
    if (ctx.exports.ContainerProxy === void 0) {
      throw new Error("ctx.exports.ContainerProxy is undefined, export ContainerProxy from the containers package in your worker entrypoint");
    }
    const interceptAll = this.shouldInterceptAllOutbound();
    if (interceptAll) {
      this.hasInterceptAllRegistration = interceptAll;
    }
    const outboundConfiguration = this.getOutboundConfiguration();
    this.persistOutboundConfiguration(outboundConfiguration);
    const hosts = this.getHostsToIntercept();
    const props = {
      enableInternet: this.enableInternet,
      containerId: this.ctx.id.toString(),
      className: this.constructor.name,
      outboundByHostOverrides: outboundConfiguration.outboundByHostOverrides,
      outboundHandlerOverride: outboundConfiguration.outboundHandlerOverride,
      allowedHosts: outboundConfiguration.allowedHosts,
      deniedHosts: outboundConfiguration.deniedHosts,
      interceptAll
    };
    const fetcher = ctx.exports.ContainerProxy({
      props
    });
    if (interceptAll) {
      for (const host of this.getStaticOutboundByHostKeys()) {
        await this.container.interceptOutboundHttp(host, fetcher);
        if (this.interceptHttps) {
          await this.container.interceptOutboundHttps(host, fetcher);
        }
      }
      if (this.interceptHttps) {
        await this.container.interceptOutboundHttps("*", fetcher);
      }
      await this.container.interceptAllOutboundHttp(fetcher);
    } else {
      for (const host of hosts) {
        await this.container.interceptOutboundHttp(host, fetcher);
        if (this.interceptHttps) {
          await this.container.interceptOutboundHttps(host, fetcher);
        }
      }
    }
  }
  /**
   * Execute SQL queries against the Container's database
   */
  sql(strings, ...values) {
    const query = strings.reduce((acc, str, i) => acc + str + (i < values.length ? "?" : ""), "");
    return [...this.ctx.storage.sql.exec(query, ...values)];
  }
  requestAndPortFromContainerFetchArgs(requestOrUrl, portOrInit, portParam) {
    let request;
    let port;
    if (requestOrUrl instanceof Request) {
      request = requestOrUrl;
      port = typeof portOrInit === "number" ? portOrInit : void 0;
    } else {
      const url = typeof requestOrUrl === "string" ? requestOrUrl : requestOrUrl.toString();
      const init = typeof portOrInit === "number" ? {} : portOrInit || {};
      port = typeof portOrInit === "number" ? portOrInit : typeof portParam === "number" ? portParam : void 0;
      request = new Request(url, init);
    }
    port ??= this.defaultPort;
    if (port === void 0) {
      throw new Error("No port specified for container fetch. Set defaultPort or specify a port parameter.");
    }
    return { request, port };
  }
  /**
   *
   * The method prioritizes port sources in this order:
   * 1. Ports specified directly in the method call
   * 2. `requiredPorts` class property (if set)
   * 3. `defaultPort` (if neither of the above is specified)
   * 4. Falls back to port 33 if none of the above are set
   */
  async getPortsToCheck(overridePorts) {
    if (overridePorts !== void 0) {
      return Array.isArray(overridePorts) ? overridePorts : [overridePorts];
    }
    if (this.requiredPorts && this.requiredPorts.length > 0) {
      return [...this.requiredPorts];
    }
    return [this.defaultPort ?? FALLBACK_PORT_TO_CHECK];
  }
  // ===========================================
  //     CONTAINER INTERACTION & MONITORING
  // ===========================================
  /**
   * Tries to start a container if it's not already running
   * Returns the number of tries used
   */
  async startContainerIfNotRunning(waitOptions, options) {
    if (this.startInFlight) {
      return this.startInFlight;
    }
    if (this.container.running) {
      if (!this.monitor) {
        this.monitor = this.container.monitor();
      }
      return 0;
    }
    const startPromise = this.doStartContainer(waitOptions, options);
    this.startInFlight = startPromise;
    try {
      return await startPromise;
    } finally {
      if (this.startInFlight === startPromise) {
        this.startInFlight = void 0;
      }
    }
  }
  async doStartContainer(waitOptions, options) {
    const abortedSignal = new Promise((res) => {
      waitOptions.signal?.addEventListener("abort", () => {
        res(true);
      });
    });
    const pollInterval = waitOptions.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
    const totalTries = waitOptions.retries ?? Math.ceil(TIMEOUT_TO_GET_CONTAINER_MS / pollInterval);
    for (let tries = 0; tries < totalTries; tries++) {
      const envVars = options?.envVars ?? this.envVars;
      const entrypoint = options?.entrypoint ?? this.entrypoint;
      const enableInternet = options?.enableInternet ?? this.enableInternet;
      const labels = options?.labels ?? this.labels;
      const startConfig = {
        enableInternet
      };
      if (envVars && Object.keys(envVars).length > 0)
        startConfig.env = envVars;
      if (entrypoint)
        startConfig.entrypoint = entrypoint;
      if (labels && Object.keys(labels).length > 0)
        startConfig.labels = labels;
      this.renewActivityTimeout();
      const handleError = async () => {
        const err = await this.monitor?.catch((err2) => err2);
        if (typeof err === "number") {
          const toThrow = new Error(`Container exited before we could determine the container health, exit code: ${err}`);
          await this.state.setStoppedWithCode(err);
          this.monitor = void 0;
          try {
            await this.onError(toThrow);
          } catch {
          }
          throw toThrow;
        } else if (!isNoInstanceError(err)) {
          await this.state.setStopped();
          this.monitor = void 0;
          try {
            await this.onError(err);
          } catch {
          }
          throw err;
        }
      };
      if (tries > 0 && !this.container.running) {
        await handleError();
      }
      await this.scheduleNextAlarm();
      if (!this.container.running) {
        await this.refreshOutboundInterception();
        this.container.start(startConfig);
        this.monitor = this.container.monitor();
        await this.state.setRunning();
      } else {
        await this.scheduleNextAlarm();
      }
      this.renewActivityTimeout();
      const port = this.container.getTcpPort(waitOptions.portToCheck);
      try {
        const combinedSignal = addTimeoutSignal(waitOptions.signal, PING_TIMEOUT_MS);
        await port.fetch("http://containerstarthealthcheck", { signal: combinedSignal });
        return tries;
      } catch (error) {
        if (isNotListeningError(error) && this.container.running) {
          return tries;
        }
        if (!this.container.running && isNotListeningError(error)) {
          await handleError();
        }
        await Promise.any([
          new Promise((res) => setTimeout(res, waitOptions.waitInterval)),
          abortedSignal
        ]);
        if (waitOptions.signal?.aborted) {
          throw new Error("Aborted waiting for container to start as we received a cancellation signal", { cause: error });
        }
        if (totalTries === tries + 1) {
          if (error instanceof Error && error.message.includes("Network connection lost")) {
            this.ctx.abort();
          }
          await handleError();
          await this.state.setStopped();
          this.monitor = void 0;
          throw new Error(NO_CONTAINER_INSTANCE_ERROR, { cause: error });
        }
        continue;
      }
    }
    throw new Error(`Container did not start after ${totalTries * pollInterval}ms`);
  }
  setupMonitorCallbacks() {
    const monitor = this.monitor;
    if (!monitor || this.monitoredPromise === monitor) {
      return;
    }
    this.monitoredPromise = monitor;
    monitor.then(async () => {
      await this.ctx.blockConcurrencyWhile(async () => {
        if (this.monitor === monitor) {
          await this.state.setStoppedWithCode(0);
        }
      });
    }).catch(async (error) => {
      if (this.monitor !== monitor) {
        return;
      }
      if (isNoInstanceError(error)) {
        await this.ctx.blockConcurrencyWhile(async () => {
          if (this.monitor === monitor) {
            await this.state.setStopped();
          }
        });
        return;
      }
      const exitCode = getExitCodeFromError(error);
      if (exitCode !== null) {
        await this.ctx.blockConcurrencyWhile(async () => {
          if (this.monitor === monitor) {
            await this.state.setStoppedWithCode(exitCode);
          }
        });
        return;
      }
      await this.ctx.blockConcurrencyWhile(async () => {
        if (this.monitor === monitor) {
          await this.state.setStopped();
        }
      });
      if (this.monitor !== monitor) {
        return;
      }
      try {
        await this.onError(error);
      } catch {
      }
    }).finally(() => {
      if (this.monitor !== monitor) {
        return;
      }
      this.monitoredPromise = void 0;
      this.monitor = void 0;
      if (this.timeout) {
        if (this.resolve)
          this.resolve();
        clearTimeout(this.timeout);
      }
    });
  }
  deleteSchedules(name) {
    this.sql`DELETE FROM container_schedules WHERE callback = ${name}`;
  }
  // ============================
  //     ALARMS AND SCHEDULES
  // ============================
  /**
   * Method called when an alarm fires
   * Executes any scheduled tasks that are due
   */
  async alarm(alarmProps) {
    if (alarmProps !== void 0 && alarmProps.isRetry && alarmProps.retryCount > MAX_ALARM_RETRIES) {
      const scheduleCount = Number(this.sql`SELECT COUNT(*) as count FROM container_schedules`[0]?.count) || 0;
      const hasScheduledTasks = scheduleCount > 0;
      if (hasScheduledTasks || this.container.running) {
        await this.scheduleNextAlarm();
      }
      return;
    }
    const prevAlarm = Date.now();
    await this.ctx.storage.setAlarm(prevAlarm);
    await this.ctx.storage.sync();
    const result = this.sql`
         SELECT * FROM container_schedules;
       `;
    let minTime = Date.now() + 3 * 60 * 1e3;
    const now2 = Date.now() / 1e3;
    for (const row of result) {
      if (row.time > now2) {
        continue;
      }
      const callback = this[row.callback];
      if (!callback || typeof callback !== "function") {
        console.error(`Callback ${row.callback} not found or is not a function`);
        continue;
      }
      const schedule = this.getSchedule(row.id);
      try {
        const payload = row.payload ? JSON.parse(row.payload) : void 0;
        await callback.call(this, payload, await schedule);
      } catch (e) {
        console.error(`Error executing scheduled callback "${row.callback}":`, e);
      }
      this.sql`DELETE FROM container_schedules WHERE id = ${row.id}`;
    }
    const resultForMinTime = this.sql`
         SELECT * FROM container_schedules;
       `;
    const minTimeFromSchedules = Math.min(...resultForMinTime.map((r) => r.time * 1e3));
    if (!this.container.running) {
      await this.syncPendingStoppedEvents();
      if (resultForMinTime.length == 0) {
        await this.ctx.storage.deleteAlarm();
      } else {
        await this.ctx.storage.setAlarm(minTimeFromSchedules);
      }
      return;
    }
    if (this.isActivityExpired()) {
      await this.onActivityExpired();
      this.renewActivityTimeout();
      return;
    }
    minTime = Math.min(minTimeFromSchedules, minTime, this.sleepAfterMs);
    const timeout = Math.max(0, minTime - Date.now());
    await new Promise((resolve) => {
      this.resolve = resolve;
      if (!this.container.running) {
        resolve();
        return;
      }
      this.timeout = setTimeout(() => {
        resolve();
      }, timeout);
    });
    await this.ctx.storage.setAlarm(Date.now());
  }
  timeout;
  resolve;
  // synchronises container state with the container source of truth to process events
  async syncPendingStoppedEvents() {
    const state = await this.state.getState();
    if (!this.container.running && (state.status === "healthy" || state.status === "running")) {
      await this.callOnStop({ exitCode: 0, reason: "exit" }, state);
      return;
    }
    if (!this.container.running && state.status === "stopped_with_code") {
      await this.callOnStop({ exitCode: state.exitCode ?? 0, reason: "exit" }, state);
      return;
    }
  }
  async callOnStop(onStopParams, stateBeforeOnStop) {
    if (this.onStopCalled) {
      return;
    }
    this.onStopCalled = true;
    const promise = this.onStop(onStopParams);
    if (promise instanceof Promise) {
      await promise.finally(() => {
        this.onStopCalled = false;
      });
    } else {
      this.onStopCalled = false;
    }
    await this.state.setStoppedIfUnchanged(stateBeforeOnStop);
  }
  /**
   * Schedule the next alarm based on upcoming tasks
   */
  async scheduleNextAlarm(ms = 1e3) {
    const nextTime = ms + Date.now();
    if (this.timeout) {
      if (this.resolve)
        this.resolve();
      clearTimeout(this.timeout);
    }
    await this.ctx.storage.setAlarm(nextTime);
    await this.ctx.storage.sync();
  }
  async listSchedules(name) {
    const result = this.sql`
      SELECT * FROM container_schedules WHERE callback = ${name} LIMIT 1
    `;
    if (!result || result.length === 0) {
      return [];
    }
    return result.map(this.toSchedule);
  }
  toSchedule(schedule) {
    let payload;
    try {
      payload = JSON.parse(schedule.payload);
    } catch (e) {
      console.error(`Error parsing payload for schedule ${schedule.id}:`, e);
      payload = void 0;
    }
    if (schedule.type === "delayed") {
      return {
        taskId: schedule.id,
        callback: schedule.callback,
        payload,
        type: "delayed",
        time: schedule.time,
        delayInSeconds: schedule.delayInSeconds
      };
    }
    return {
      taskId: schedule.id,
      callback: schedule.callback,
      payload,
      type: "scheduled",
      time: schedule.time
    };
  }
  /**
   * Get a scheduled task by ID
   * @template T Type of the payload data
   * @param id ID of the scheduled task
   * @returns The Schedule object or undefined if not found
   */
  async getSchedule(id) {
    const result = this.sql`
      SELECT * FROM container_schedules WHERE id = ${id} LIMIT 1
    `;
    if (!result || result.length === 0) {
      return void 0;
    }
    const schedule = result[0];
    return this.toSchedule(schedule);
  }
  isActivityExpired() {
    if (this.inflightRequests > 0) {
      this.renewActivityTimeout();
      return false;
    }
    return this.sleepAfterMs <= Date.now();
  }
};

// state.ts
import { createHash } from "node:crypto";
var RETENTION = 30 * 86400;
var LEASE_GRACE = 900 + 120;
var DATA_CHUNK = 512 * 1024;
var digest = (s) => createHash("sha256").update(s).digest("hex");
function refuse() {
  throw new Error("verification_refused");
}
var Ledger = class {
  constructor(storage) {
    this.storage = storage;
    storage.transactionSync(() => {
      const tables = storage.sql.exec("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('meta','admissions','daily','events','outbox','chunks','admission_chunks')").toArray();
      if (tables.length) {
        const version = this.get("schema");
        if (!(version === "verifier-state-v1" && tables.length === 6 || version === "verifier-state-v2" && tables.length === 7)) refuse();
        for (const k of ["clock", "active", "lease", "wake", "task"]) if (this.get(k) === void 0) refuse();
        if (version === "verifier-state-v1") {
          storage.sql.exec("CREATE TABLE admission_chunks(id TEXT NOT NULL,n INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(id,n))");
          for (const row of storage.sql.exec("SELECT id,record FROM admissions")) {
            const r = JSON.parse(row.record);
            if (r.id !== row.id || typeof r.snapshot !== "string" || !Array.isArray(r.objects)) refuse();
            storage.sql.exec("UPDATE admissions SET record=? WHERE id=?", this.pack(r), row.id);
          }
          this.put("schema", "verifier-state-v2");
        }
        return;
      }
      storage.sql.exec(`CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS admissions(id TEXT PRIMARY KEY,hash TEXT NOT NULL,iid TEXT UNIQUE NOT NULL,nonce TEXT UNIQUE NOT NULL,authorization TEXT UNIQUE NOT NULL,record TEXT NOT NULL,until INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS daily(listing TEXT NOT NULL,day TEXT NOT NULL,n INTEGER NOT NULL,PRIMARY KEY(listing,day));
        CREATE TABLE IF NOT EXISTS events(at INTEGER NOT NULL,event TEXT NOT NULL,hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,hash TEXT NOT NULL,bytes INTEGER NOT NULL,chunks INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS chunks(id TEXT NOT NULL,n INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(id,n));
        CREATE TABLE IF NOT EXISTS admission_chunks(id TEXT NOT NULL,n INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(id,n));`);
      this.put("schema", "verifier-state-v2");
      for (const [k, v] of Object.entries({ clock: "0", active: "", lease: "0", wake: "0", task: "" })) this.put(k, v);
    });
  }
  storage;
  get(k) {
    return this.storage.sql.exec("SELECT v FROM meta WHERE k=?", k).toArray()[0]?.v;
  }
  put(k, v) {
    this.storage.sql.exec("INSERT OR REPLACE INTO meta VALUES (?,?)", k, v);
  }
  event(event, hash, now2) {
    this.storage.sql.exec("INSERT INTO events VALUES (?,?,?)", now2, event, hash);
  }
  clock(now2) {
    const last = Number(this.get("clock") ?? 0);
    if (!Number.isSafeInteger(now2) || now2 < last - 300) refuse();
    this.put("clock", String(Math.max(now2, last)));
  }
  observe(now2) {
    this.storage.transactionSync(() => this.clock(now2));
  }
  firstStart(wrap, now2) {
    return this.storage.transactionSync(() => {
      this.clock(now2);
      if (this.get("bootstrap")) {
        if (!this.get("wrap") || !this.get("secret")) refuse();
        return false;
      }
      if (this.get("wrap") || this.get("secret") || this.storage.sql.exec("SELECT id FROM admissions LIMIT 1").toArray().length) refuse();
      this.put("bootstrap", "initializing");
      this.put("wrap", wrap);
      this.event("bootstrap", "", now2);
      return true;
    });
  }
  pack(r) {
    const { snapshot, objects, ...meta } = r;
    if (["reported", "expired", "interrupted"].includes(r.state)) return JSON.stringify({ ...meta, snapshot: "", objects: [] });
    const body = JSON.stringify({ snapshot, objects }).replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
    const chunks = Math.ceil(body.length / DATA_CHUNK);
    for (let n = 0; n < chunks; n++) this.storage.sql.exec("INSERT INTO admission_chunks VALUES (?,?,?)", r.id, n, body.slice(n * DATA_CHUNK, (n + 1) * DATA_CHUNK));
    return JSON.stringify({ ...meta, data: { chunks, bytes: body.length, hash: digest(body) } });
  }
  record(id) {
    return this.storage.transactionSync(() => {
      const row = this.storage.sql.exec("SELECT record FROM admissions WHERE id=?", id).toArray()[0];
      if (!row) return;
      const { data, ...meta } = JSON.parse(row.record);
      if (!data) {
        if (!["reported", "expired", "interrupted"].includes(meta.state) || meta.snapshot !== "" || !Array.isArray(meta.objects) || meta.objects.length) refuse();
        return { ...meta, snapshot: "", objects: [] };
      }
      const chunks = this.storage.sql.exec("SELECT n,data FROM admission_chunks WHERE id=? ORDER BY n", id).toArray();
      if (!Number.isSafeInteger(data.chunks) || data.chunks < 1 || chunks.length !== data.chunks || chunks.some((c, i) => c.n !== i || !c.data.length || c.data.length > DATA_CHUNK || /[^\x00-\x7f]/.test(c.data))) refuse();
      const body = chunks.map((c) => c.data).join("");
      if (body.length !== data.bytes || digest(body) !== data.hash) refuse();
      const payload = JSON.parse(body);
      if (typeof payload.snapshot !== "string" || !Array.isArray(payload.objects) || payload.objects.length > 17033) refuse();
      return { ...meta, snapshot: payload.snapshot, objects: payload.objects };
    });
  }
  active() {
    const id = this.get("active");
    if (!id) return;
    return this.record(id) ?? refuse();
  }
  wake(now2) {
    return this.storage.transactionSync(() => {
      this.clock(now2);
      const wake = Number(this.get("wake") ?? 0), lease = Number(this.get("lease") ?? 0);
      const task = this.get("task"), marker = task === "queued" ? wake : lease || wake;
      if (wake > now2 - 60 || task && now2 <= marker + LEASE_GRACE) return false;
      this.put("wake", String(now2));
      this.put("task", "queued");
      return true;
    });
  }
  claim(now2) {
    return this.storage.transactionSync(() => {
      this.clock(now2);
      const lease = Number(this.get("lease") ?? 0);
      if (lease && now2 <= lease + LEASE_GRACE) return false;
      this.put("lease", String(now2));
      this.put("task", "running");
      return true;
    });
  }
  release() {
    this.storage.transactionSync(() => {
      this.put("lease", "0");
      this.put("task", "");
    });
  }
  admit(job, snapshot, objects, now2, pickup, start) {
    return this.storage.transactionSync(() => {
      this.clock(now2);
      const p = job.Payload;
      const existing = this.record(p.spec_id);
      if (existing) {
        if (existing.token !== job.Token || existing.hash !== job.Envelope.spec_hash) refuse();
        return;
      }
      if (this.active() || now2 > Date.parse(p.expires_at_utc) / 1e3 || now2 > Date.parse(p.accepted_at_utc) / 1e3 + 86400 || now2 > pickup + 1920) refuse();
      const day = new Date(now2 * 1e3).toISOString().slice(0, 10);
      const n = this.storage.sql.exec("SELECT n FROM daily WHERE listing=? AND day=?", p.listing_id, day).toArray()[0]?.n ?? 0;
      if (n >= 10) refuse();
      const r = { id: p.spec_id, token: job.Token, hash: job.Envelope.spec_hash, iid: job.Envelope.iid, variant: job.Envelope.variant, snapshot, objects, pickup, start, state: "accepted" };
      this.storage.sql.exec("INSERT INTO admissions VALUES (?,?,?,?,?,?,?)", r.id, r.hash, r.iid, p.nonce, p.owner_authorization_id, this.pack(r), now2 + RETENTION);
      this.storage.sql.exec("INSERT OR REPLACE INTO daily VALUES (?,?,?)", p.listing_id, day, n + 1);
      this.put("active", r.id);
      this.event("accepted", r.hash, now2);
      return r;
    });
  }
  commit(r, body, hash, now2) {
    const bytes = new TextEncoder().encode(body);
    if (!bytes.length || bytes.length > 2 << 20 || !/^[a-f0-9]{64}$/.test(hash)) refuse();
    if ([...body].some((c) => c.charCodeAt(0) > 127)) refuse();
    this.storage.transactionSync(() => {
      this.clock(now2);
      const current = this.record(r.id);
      if (!current || current.state !== "accepted" || this.get("active") !== r.id || now2 > r.pickup + 1920) refuse();
      const count = Math.ceil(body.length / 131072);
      for (let n = 0; n < count; n++) this.storage.sql.exec("INSERT INTO chunks VALUES (?,?,?)", r.id, n, body.slice(n * 131072, (n + 1) * 131072));
      this.storage.sql.exec("INSERT INTO outbox VALUES (?,?,?,?)", r.id, hash, bytes.length, count);
      this.update({ ...current, state: "committed" }, now2);
      this.event("committed", r.hash, now2);
    });
  }
  body(r) {
    return this.storage.transactionSync(() => {
      const d = this.storage.sql.exec("SELECT * FROM outbox WHERE id=?", r.id).toArray()[0];
      const chunks = this.storage.sql.exec("SELECT n,data FROM chunks WHERE id=? ORDER BY n", r.id).toArray();
      if (!d || chunks.length !== d.chunks || chunks.some((c, i) => c.n !== i)) refuse();
      const body = chunks.map((c) => c.data).join("");
      if (body.length !== d.bytes) refuse();
      return { body, hash: d.hash };
    });
  }
  update(r, now2) {
    const { snapshot, objects, ...meta } = r;
    const row = this.storage.sql.exec("SELECT record FROM admissions WHERE id=?", r.id).toArray()[0] ?? refuse();
    const saved = JSON.parse(row.record);
    this.storage.sql.exec("UPDATE admissions SET record=?,until=? WHERE id=?", JSON.stringify({ ...meta, ...saved.data ? { data: saved.data } : { snapshot: "", objects: [] } }), now2 + RETENTION, r.id);
  }
  settle(r, state, now2) {
    this.storage.transactionSync(() => {
      this.clock(now2);
      this.update({ ...r, state }, now2);
      this.event(state, r.hash, now2);
      this.storage.sql.exec("DELETE FROM chunks WHERE id=?", r.id);
      this.storage.sql.exec("DELETE FROM outbox WHERE id=?", r.id);
      this.storage.sql.exec("UPDATE admissions SET record=json_set(json_remove(record,'$.data'),'$.snapshot','','$.objects',json('[]')) WHERE id=?", r.id);
      this.storage.sql.exec("DELETE FROM admission_chunks WHERE id=?", r.id);
      this.put("active", "");
    });
  }
  prune(now2) {
    this.storage.transactionSync(() => {
      this.storage.sql.exec("DELETE FROM admissions WHERE until<? AND id NOT IN (SELECT id FROM outbox) AND id!=? AND json_extract(record,'$.state') IN ('reported','expired','interrupted')", now2, this.get("active") ?? "");
      this.storage.sql.exec("DELETE FROM admission_chunks WHERE id NOT IN (SELECT id FROM admissions)");
      this.storage.sql.exec("DELETE FROM events WHERE at<?", now2 - RETENTION);
      this.storage.sql.exec("DELETE FROM daily WHERE day<?", new Date((now2 - RETENTION) * 1e3).toISOString().slice(0, 10));
    });
  }
};

// crypto.ts
var utf8 = new TextEncoder();
var now = () => Math.floor(Date.now() / 1e3);
function b64(b) {
  return btoa(String.fromCharCode(...b)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function unb64(s) {
  return Uint8Array.from(atob(s.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
}
function random() {
  return b64(crypto.getRandomValues(new Uint8Array(32)));
}
async function sha(s) {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", typeof s === "string" ? utf8.encode(s) : s)), (b) => b.toString(16).padStart(2, "0")).join("");
}
function canonical(v) {
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (v !== null && typeof v === "object") return "{" + Object.entries(v).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, v2]) => canonical(k) + ":" + canonical(v2)).join(",") + "}";
  const s = JSON.stringify(v);
  if (s === void 0) refuse();
  return s.replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}
function deploymentConfigCanonical(v) {
  if (typeof v === "string") {
    for (const c of v) {
      const cp = c.codePointAt(0);
      if (cp >= 55296 && cp <= 57343) refuse();
    }
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(deploymentConfigCanonical).join(",") + "]";
  if (v !== null && typeof v === "object") {
    const compare = (a, b) => {
      const x = Array.from(a, (c) => c.codePointAt(0)), y = Array.from(b, (c) => c.codePointAt(0));
      for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
      return x.length - y.length;
    };
    return "{" + Object.entries(v).sort(([a], [b]) => compare(a, b)).map(([k, z]) => deploymentConfigCanonical(k) + ":" + deploymentConfigCanonical(z)).join(",") + "}";
  }
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  return refuse();
}
async function encrypt(wrap, connection, value) {
  const key = await crypto.subtle.importKey("raw", unb64(wrap), "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8.encode(connection + "/secret-v1") }, key, utf8.encode(JSON.stringify(value)));
  return JSON.stringify({ iv: b64(iv), cipher: Array.from(new Uint8Array(cipher), (b) => b.toString(16).padStart(2, "0")).join("") });
}
async function decrypt(wrap, connection, value) {
  try {
    const v = JSON.parse(value);
    if (Object.keys(v).sort().join(" ") !== "cipher iv" || typeof v.iv !== "string" || unb64(v.iv).length !== 12 || typeof v.cipher !== "string" || !/^[0-9a-f]+$/.test(v.cipher) || v.cipher.length % 2 || v.cipher.length > 4 * 1048576) refuse();
    const key = await crypto.subtle.importKey("raw", unb64(wrap), "AES-GCM", false, ["decrypt"]);
    const cipher = Uint8Array.from(v.cipher.match(/../g), (s) => parseInt(s, 16));
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(v.iv), additionalData: utf8.encode(connection + "/secret-v1") }, key, cipher);
    return JSON.parse(new TextDecoder().decode(plain));
  } catch {
    return refuse();
  }
}
async function equalSecret(a, b) {
  const x = await sha(a), y = await sha(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}
async function bounded(response, limit) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let n = 0;
  try {
    for (; ; ) {
      const r = await reader.read();
      if (r.done) break;
      n += r.value.length;
      if (n > limit) refuse();
      chunks.push(r.value);
    }
  } finally {
    await reader.cancel();
  }
  const out = new Uint8Array(n);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(out);
}

// worker.ts
var releaseFields = "binary_sha256 jurisdiction release_id scanner_version worker_identity";
function identity(raw) {
  let c;
  try {
    c = JSON.parse(raw);
  } catch {
    refuse();
  }
  if (!c || Object.keys(c).sort().join(" ") !== releaseFields || c.jurisdiction !== "default" || typeof c.release_id !== "string" || typeof c.scanner_version !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(c.release_id) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(c.scanner_version) || !/^[a-f0-9]{64}$/.test(c.binary_sha256) || !c.worker_identity || Object.keys(c.worker_identity).sort().join(" ") !== "mode sha256" || !/^[a-f0-9]{64}$/.test(c.worker_identity.sha256) || !["bundle", "source_tree_lockfile"].includes(c.worker_identity.mode)) refuse();
  return c;
}
function config(c) {
  identity(canonical(Object.fromEntries(releaseFields.split(" ").map((k) => [k, c[k]]))));
  if (Object.keys(c).sort().join(" ") !== "binary_sha256 bucket connection_id jurisdiction keys prefix release_id scanner_version worker_identity" || !/^[0-9a-f-]{36}$/.test(c.connection_id) || typeof c.bucket !== "string" || !c.bucket || /[/:*?\\\x00]/.test(c.bucket) || typeof c.prefix !== "string" || !Array.isArray(c.keys) || c.keys.length === 0 || c.keys.length > 17033 || utf8.encode(deploymentConfigCanonical(c)).length > 1048576 || c.keys.some((k) => typeof k !== "string" || !k || k.includes("\0") || !k.startsWith(c.prefix)) || new Set(c.keys).size !== c.keys.length) refuse();
  return c;
}
function matches(c, i) {
  return releaseFields.split(" ").every((k) => canonical(c[k]) === canonical(i[k]));
}
function verifier(env) {
  return env.VERIFIER.get(env.VERIFIER.idFromName("aim-verifier"));
}
async function signingKey(secret) {
  const seed = unb64(secret.Private.replaceAll("+", "-").replaceAll("/", "_"));
  if (seed.length !== 64) refuse();
  const der = new Uint8Array(48);
  der.set([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32]);
  der.set(seed.slice(0, 32), 16);
  return crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, false, ["sign"]);
}
async function marketplace(c, s, path, body, limit) {
  if (!/^\/api\/v1\/verification-runners\/[a-f0-9-]{36}\/(work|report)$/.test(path)) refuse();
  const claims = { runner_id: s.Runner, kind: "cloudflare", connection_id: c.connection_id, release_id: c.release_id, scanner_version: c.scanner_version, binary_sha256: c.binary_sha256, worker_identity: c.worker_identity, method: "POST", path, nonce: random(), iat: now(), body_sha256: await sha(body) };
  const token = b64(utf8.encode(canonical({ alg: "EdDSA", typ: "aim-verification-request+jwt", kid: s.Receipt }))) + "." + b64(utf8.encode(canonical(claims)));
  const jws = token + "." + b64(new Uint8Array(await crypto.subtle.sign("Ed25519", await signingKey(s), utf8.encode(token))));
  if (jws.length > 4096) refuse();
  const response = await fetch("https://api.ai.market" + path, { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + jws }, body, redirect: "manual", signal: AbortSignal.timeout(3e4) });
  if (response.status !== 200) refuse();
  return bounded(response, limit);
}
async function capability(wrap, payload) {
  const text = b64(utf8.encode(canonical(payload)));
  const key = await crypto.subtle.importKey("raw", unb64(wrap), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return text + "." + b64(new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8.encode("bridge-v1." + text))));
}
var CloudflareVerifier = class extends Container {
  defaultPort = 8080;
  sleepAfter = "20m";
  enableInternet = true;
  ledger;
  static outboundByHost = {
    "r2-bridge.internal": async (request, env, _ctx) => {
      const u = new URL(request.url);
      if (u.protocol !== "http:" || u.hostname !== "r2-bridge.internal" || u.port && u.port !== "80") return new Response("verification_refused", { status: 403 });
      return verifier(env).fetch(request);
    }
  };
  constructor(ctx, env) {
    super(ctx, env);
    this.ledger = new Ledger(ctx.storage);
  }
  async fetch(request) {
    try {
      return await this.bridge(request);
    } catch {
      return new Response("verification_refused", { status: 403 });
    }
  }
  async bridge(request) {
    const u = new URL(request.url);
    if (u.protocol !== "http:" || u.hostname !== "r2-bridge.internal" || u.search || !["HEAD", "GET"].includes(request.method) || !/^\/member\/(0|[1-9][0-9]*)$/.test(u.pathname)) refuse();
    const c = await this.runtimeConfig(), r = this.ledger.active(), wrap = this.ledger.get("wrap"), saved = this.ledger.get("capability");
    const token = request.headers.get("Authorization")?.replace(/^Bearer /, "");
    if (!r || r.state !== "accepted" || !wrap || !saved || !token || token.length > 4096 || !await equalSecret(token, saved)) refuse();
    const parts = token.split(".");
    if (parts.length !== 2) refuse();
    const p = JSON.parse(new TextDecoder().decode(unb64(parts[0])));
    if (await capability(wrap, p) !== token || p.connection !== c.connection_id || p.spec !== r.hash || p.id !== this.ctx.id.toString() || p.start !== r.start || now() > p.exp || now() > r.start + 780) refuse();
    const index = Number(u.pathname.slice(8)), m = r.objects[index];
    if (!m || !c.keys.includes(m.Key) || !m.Key.startsWith(c.prefix)) refuse();
    let range;
    const header = request.headers.get("Range");
    if (header) {
      const match = /^bytes=(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$/.exec(header);
      if (!match || request.method !== "GET") refuse();
      const offset = Number(match[1]), end = Number(match[2]);
      if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(end) || end < offset || end >= m.Size) refuse();
      range = { offset, length: end - offset + 1 };
    }
    if (request.method === "HEAD") {
      const head = await this.env.SOURCE.head(m.Key);
      if (!head || head.etag !== m.ETag || head.size !== m.Size) refuse();
      return new Response(null, { headers: { "X-Object-Size": String(head.size), "X-Object-Etag": head.etag, "Cache-Control": "no-store" } });
    }
    const object = await this.env.SOURCE.get(m.Key, { onlyIf: { etagMatches: m.ETag }, ...range ? { range } : {} });
    if (!object || object.etag !== m.ETag || object.size !== m.Size || !("body" in object) || !object.body) refuse();
    const headers = new Headers({ "X-Object-Size": String(object.size), "X-Object-Etag": object.etag, "Cache-Control": "no-store" });
    if (range) {
      const got = object.range;
      if (!got || !("offset" in got) || !("length" in got) || got.offset !== range.offset || got.length !== range.length) refuse();
      headers.set("X-Range-Offset", String(range.offset));
      headers.set("X-Range-Length", String(range.length));
    } else if (object.range && (!("offset" in object.range) || !("length" in object.range) || object.range.offset !== 0 || object.range.length !== m.Size)) refuse();
    return new Response(object.body, { status: range ? 206 : 200, headers });
  }
  operatorPage() {
    return `<!doctype html><meta charset="utf-8"><title>Verifier control</title><h1>Run a check</h1><p>Enter your seller control secret. Scheduled checks are a best-effort backstop.</p><input id="secret" type="password" autocomplete="off"><button id="run">Run now</button><p id="result"></p><script>document.getElementById('run').onclick=async()=>{const input=document.getElementById('secret');const secret=input.value;input.value='';const r=await fetch('/operator/run-now',{method:'POST',headers:{Authorization:'Bearer '+secret,'Content-Type':'application/json'},body:'{}'});document.getElementById('result').textContent=r.status===202?'Check scheduled':'Check refused';};</script>`;
  }
  async enqueue() {
    identity(this.env.DEPLOYMENT_CONFIG);
    if (this.ledger.get("bootstrap")) await this.runtimeConfig();
    if (this.ledger.wake(now())) {
      try {
        await this.schedule(1, "pollTask");
      } catch (e) {
        this.ledger.release();
        throw e;
      }
    }
  }
  async runtimeConfig() {
    const count = Number(this.ledger.get("config_chunks")), hash = this.ledger.get("config_hash");
    if (!Number.isSafeInteger(count) || count < 1 || count > 2 || !hash) refuse();
    const chunks = [];
    let size = 0;
    for (let n = 0; n < count; n++) {
      const data = this.ledger.storage.sql.exec("SELECT CAST(v AS BLOB) data FROM meta WHERE k=?", "config_" + n).toArray()[0]?.data ?? refuse();
      if (data.byteLength < 1 || size + data.byteLength > 1048576) refuse();
      chunks.push(data);
      size += data.byteLength;
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const data of chunks) {
      bytes.set(new Uint8Array(data), offset);
      offset += data.byteLength;
    }
    if (await sha(bytes) !== hash) refuse();
    const raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const c = config(JSON.parse(raw));
    if (deploymentConfigCanonical(c) !== raw || !matches(c, identity(this.env.DEPLOYMENT_CONFIG)) || c.connection_id !== this.ledger.get("connection_id")) refuse();
    return c;
  }
  persistConfig(c, hash, tokenHash) {
    const existing = this.ledger.get("connection_id");
    if (existing && existing !== c.connection_id) refuse();
    const bytes = utf8.encode(deploymentConfigCanonical(c)), count = Math.ceil(bytes.length / 524288);
    for (let n = 0; n < count; n++) this.ledger.storage.sql.exec("INSERT OR REPLACE INTO meta VALUES (?,?)", "config_" + n, bytes.slice(n * 524288, (n + 1) * 524288));
    this.ledger.put("config_chunks", String(count));
    this.ledger.put("config_hash", hash);
    this.ledger.put("connection_id", c.connection_id);
    this.ledger.put("config_token_hash", tokenHash);
  }
  async pullConfig() {
    const i = identity(this.env.DEPLOYMENT_CONFIG), token = this.env.REGISTRATION_TOKEN;
    if (typeof token !== "string" || unb64(token).length !== 32) refuse();
    const response = await fetch("https://api.ai.market/api/v1/verification-runners/cloudflare/deployment-config", { method: "POST", headers: { "Content-Type": "application/json" }, body: canonical({ registration_token: token }), redirect: "manual", signal: AbortSignal.timeout(3e4) });
    if (response.status !== 200) refuse();
    const result = JSON.parse(await bounded(response, (1 << 20) + 256));
    if (!result || Object.keys(result).sort().join(" ") !== "deployment_config deployment_config_sha256" || !/^[a-f0-9]{64}$/.test(result.deployment_config_sha256) || await sha(deploymentConfigCanonical(result.deployment_config)) !== result.deployment_config_sha256) refuse();
    const c = config(result.deployment_config);
    if (!matches(c, i) || this.ledger.get("connection_id") && this.ledger.get("connection_id") !== c.connection_id) refuse();
    return { config: c, hash: result.deployment_config_sha256, tokenHash: await sha(token) };
  }
  async save(secret, c) {
    const wrap = this.ledger.get("wrap") ?? refuse();
    const cipher = await encrypt(wrap, c.connection_id, secret);
    this.ctx.storage.transactionSync(() => {
      this.ledger.put("secret", cipher);
      this.ledger.put("bootstrap", "saved");
    });
  }
  async load(c) {
    const wrap = this.ledger.get("wrap"), cipher = this.ledger.get("secret");
    if (!wrap || !cipher) refuse();
    const s = await decrypt(wrap, c.connection_id, cipher);
    if (s.Connection !== c.connection_id || s.Version !== c.scanner_version || s.Release !== c.release_id || s.Digest !== c.binary_sha256 || canonical(s.Worker) !== canonical(c.worker_identity)) refuse();
    return s;
  }
  async compute(path, c, secret, extra = {}) {
    const response = await this.containerFetch("http://localhost" + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ config: { ...c, deployment_config_sha256: this.ledger.get("config_hash") }, ...secret ? { secret } : {}, ...extra }), signal: AbortSignal.timeout(89e4) });
    if (response.status === 409 && await bounded(response, 64) === "registration_refused\n") throw new Error("registration_refused");
    if (response.status !== 200) refuse();
    return JSON.parse(await bounded(response, 18 << 20));
  }
  async recover(c, s) {
    let r = this.ledger.active();
    if (!r) return;
    if (now() > r.pickup + 1920) {
      this.ledger.settle(r, "expired", now());
      return;
    }
    if (r.state !== "committed") {
      if (now() <= r.start + LEASE_GRACE) refuse();
      if (r.variant === "probe") {
        this.ledger.settle(r, "interrupted", now());
        return;
      }
      const terminal = await this.compute("/terminal", c, s, { token: r.token, pickup: r.pickup });
      this.ledger.commit(r, terminal.body, await sha(terminal.body), now());
      r = this.ledger.active() ?? refuse();
    }
    const out = this.ledger.body(r);
    if (await sha(out.body) !== out.hash || now() > r.pickup + 1920) refuse();
    const raw = await marketplace(c, s, "/api/v1/verification-runners/" + s.Runner + "/report", out.body, 4096);
    const ack = JSON.parse(raw);
    if (canonical(ack) !== raw || Object.keys(ack).sort().join(" ") !== "iid status" || ack.iid !== r.iid || ack.status !== "stored") refuse();
    this.ledger.settle(r, "reported", now());
    console.log(JSON.stringify({ event: "reported", hash: r.hash }));
  }
  async pollTask() {
    const start = now();
    if (!this.ledger.claim(start)) {
      await this.schedule(Math.max(1, Number(this.ledger.get("lease")) + LEASE_GRACE + 1 - start), "pollTask");
      return;
    }
    try {
      let c;
      if (!this.ledger.get("bootstrap")) {
        if (["wrap", "secret", "config_hash", "config_chunks", "connection_id"].some((k) => this.ledger.get(k) !== void 0) || this.ctx.storage.sql.exec("SELECT id FROM admissions LIMIT 1").toArray().length) refuse();
        const pulled = await this.pullConfig();
        this.ctx.storage.transactionSync(() => {
          if (!this.ledger.firstStart(random(), now())) refuse();
          this.persistConfig(pulled.config, pulled.hash, pulled.tokenHash);
        });
        c = await this.runtimeConfig();
        const sec2 = await this.compute("/create", { ...c, registration_token: this.env.REGISTRATION_TOKEN });
        await this.save(sec2, c);
      } else c = await this.runtimeConfig();
      let sec = await this.load(c);
      if (!sec.Runner) {
        try {
          sec = await this.compute("/register", c, sec);
          await this.save(sec, c);
        } catch (e) {
          if (!(e instanceof Error) || e.message !== "registration_refused") throw e;
          const replaced = await sha(this.env.REGISTRATION_TOKEN) !== this.ledger.get("config_token_hash");
          const pulled = replaced ? await this.pullConfig() : void 0;
          const request = JSON.parse(new TextDecoder().decode(unb64(sec.Registration)));
          delete request.key_proof;
          if (pulled) {
            request.registration_token = this.env.REGISTRATION_TOKEN;
            request.deployment_config_sha256 = pulled.hash;
          }
          request.registration_nonce = random();
          request.registered_at_utc = new Date(now() * 1e3).toISOString().replace(".000Z", "Z");
          request.key_proof = b64(new Uint8Array(await crypto.subtle.sign("Ed25519", await signingKey(sec), utf8.encode(canonical(request)))));
          sec = { ...sec, Nonce: request.registration_nonce, Registration: btoa(canonical(request)) };
          const cipher = await encrypt(this.ledger.get("wrap") ?? refuse(), c.connection_id, sec);
          this.ctx.storage.transactionSync(() => {
            if (pulled) this.persistConfig(pulled.config, pulled.hash, pulled.tokenHash);
            this.ledger.put("secret", cipher);
          });
          c = await this.runtimeConfig();
          sec = await this.compute("/register", c, sec);
          await this.save(sec, c);
        }
      }
      await this.recover(c, sec);
      const pickup = now();
      const raw = await marketplace(c, sec, "/api/v1/verification-runners/" + sec.Runner + "/work", "{}", 64 << 10);
      const response = JSON.parse(raw);
      if (canonical(response) !== raw || Object.keys(response).join() !== "work_jws" || !(response.work_jws === null || typeof response.work_jws === "string")) refuse();
      this.ledger.put("last_poll", String(now()));
      if (response.work_jws === null) return;
      const token = response.work_jws, hash = await sha(token);
      this.ledger.event("received", hash, now());
      console.log(JSON.stringify({ event: "received", hash }));
      const replay = this.ctx.storage.sql.exec("SELECT record FROM admissions WHERE json_extract(record,'$.token')=?", token).toArray()[0];
      if (replay) return;
      const prepared = await this.compute("/prepare", c, sec, { token });
      if (prepared.rotation && prepared.secret) {
        await this.save(prepared.secret, c);
        return;
      }
      const admitted = this.ledger.admit(prepared.job, prepared.snapshot, prepared.objects, now(), pickup, start);
      if (!admitted) return;
      console.log(JSON.stringify({ event: "accepted", hash: admitted.hash }));
      const cap = await capability(this.ledger.get("wrap") ?? refuse(), { connection: c.connection_id, spec: admitted.hash, start: admitted.start, exp: admitted.start + 780, id: this.ctx.id.toString(), nonce: random() });
      this.ledger.put("capability", cap);
      const result = await this.compute("/execute", c, sec, { token, snapshot: prepared.snapshot, capability: cap, start, pickup });
      this.ledger.commit(admitted, result.body, await sha(result.body), now());
      console.log(JSON.stringify({ event: "committed", hash: admitted.hash }));
      await this.recover(c, sec);
    } catch {
      this.ledger.event("refused", "", now());
      console.log(JSON.stringify({ event: "refused" }));
    } finally {
      this.ledger.release();
      this.ledger.prune(now());
      await this.stop();
    }
  }
};
var worker_default = {
  async fetch(request, env) {
    const u = new URL(request.url), headers = { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'" };
    if (u.pathname === "/operator" && request.method === "GET" && !u.search) {
      return new Response(await verifier(env).operatorPage(), { headers: { ...headers, "Content-Type": "text/html; charset=utf-8" } });
    }
    if (u.pathname !== "/operator/run-now" || request.method !== "POST" || u.search) return new Response("Not found", { status: 404, headers });
    if (!env.RUN_NOW_SECRET || !/^[A-Za-z0-9_-]{43}$/.test(env.RUN_NOW_SECRET) || !await equalSecret(request.headers.get("Authorization") ?? "", "Bearer " + env.RUN_NOW_SECRET)) return new Response("Unauthorized", { status: 401, headers });
    try {
      if (await bounded(new Response(request.body), 3) !== "{}") refuse();
      await verifier(env).enqueue();
      return new Response(null, { status: 202, headers });
    } catch {
      return new Response("verification_refused", { status: 400, headers });
    }
  },
  async scheduled(_controller, env) {
    await verifier(env).enqueue();
  }
};
export {
  CloudflareVerifier,
  ContainerProxy,
  config,
  worker_default as default,
  identity
};
