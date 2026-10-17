#!/usr/bin/env python3
"""Evidence-only S1807 trial. No Cloudflare calls in dry-run or self-test."""
import argparse
import base64
import contextlib
import hashlib
import hmac
import io
import json
import logging
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import sys
import time
import termios
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx


APPROVED_ACCOUNT = "d5346d3e0f8f344c5f4915aaca689adf"  # safety boundary, not a secret
SCOPES = "workers-scripts.admin containers.write"
REDIRECT = "http://127.0.0.1:8976/callback"
API = "https://api.cloudflare.com/client/v4"
OAUTH = "https://dash.cloudflare.com/oauth2"
COMMIT = "f13e6d7a9052a3bff36d5e27d32212cfdf3305a2"
ARTIFACT = f"https://raw.githubusercontent.com/aidotmarket/cloudflare-verifier-v0.1.1/{COMMIT}/worker.mjs"
BUNDLE_SHA = "69e62e36aee28c96521ca6e06d93b82532d3314db50a4ec09f18786d220b54d4"
BINARY_SHA = "45b5bf95b784bf6cc572fe84f8faba77bb09682a3d5cb1f25cae6eb4e6a1c8a6"
ROOT = Path("/Users/max/koskadeux-state/s1807/cf-oauth-trial")
IMAGE_RE = r"(?:[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]+)?/)?[a-z0-9][a-z0-9._/-]*@sha256:[a-fA-F0-9]{64}"
REUSE_APP = "a030d580-f639-48c8-9627-f10c1f3ce6e4"
DENIED_NAMES = ("aim-cloudflare-verifier", "allai-dead-man-switch", "get-ai-market", "vectoraiz-installer")


def authorize_url(client_id, state, verifier):
    return OAUTH + "/auth?" + urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
        "scope": SCOPES, "state": state,
        "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256"})


def manual_code(value, state):
    try:
        parsed = urlsplit(value)
        require(value.startswith(REDIRECT + "?") and
                (parsed.scheme, parsed.netloc, parsed.hostname, parsed.port, parsed.path) ==
                ("http", "127.0.0.1:8976", "127.0.0.1", 8976, "/callback") and
                not parsed.fragment and not any(c.isspace() for c in value), "callback_url_refused")
        code = callback_code(value, parsed.netloc, state)
        require(code is not None, "callback_state_or_code_refused")
        return code
    except ValueError:
        raise Refusal("callback_url_refused") from None



class Refusal(Exception):
    """Only locally authored, nonsecret reason codes belong in this exception."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def metadata(bucket=None):
    identity = {"binary_sha256": BINARY_SHA, "jurisdiction": "default",
                "release_id": "cloudflare-verifier-v0.1.1", "scanner_version": "0.1.1",
                "worker_identity": {"mode": "bundle", "sha256": BUNDLE_SHA}}
    bindings = [{"type": "durable_object_namespace", "name": "VERIFIER",
                 "class_name": "CloudflareVerifier"},
                {"type": "plain_text", "name": "DEPLOYMENT_CONFIG",
                 "text": json.dumps(identity, sort_keys=True, separators=(",", ":"))}]
    if bucket:
        bindings.append({"type": "r2_bucket", "name": "SOURCE", "bucket_name": bucket})
    return {"main_module": "worker.mjs", "compatibility_date": "2026-10-06",
            "compatibility_flags": ["nodejs_compat"], "bindings": bindings,
            "containers": [{"class_name": "CloudflareVerifier"}],
            "migrations": {"new_tag": "v1", "steps": [
                {"new_sqlite_classes": ["CloudflareVerifier"]}]},
            "observability": {"enabled": False}}


def multipart(bundle, meta):
    # Build without a client or transport; httpx does the MIME encoding only.
    request = httpx.Request("PUT", API + "/unused", files={
        "metadata": (None, json.dumps(meta), "application/json"),
        "worker.mjs": ("worker.mjs", bundle, "application/javascript+module")})
    return request.read(), request.headers["Content-Type"]


def module_bytes(content, content_type):
    if content_type.lower().startswith("multipart/"):
        message = BytesParser(policy=policy.default).parsebytes(
            ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + content)
        parts = [p.get_payload(decode=True) for p in message.walk()
                 if p.get_filename() == "worker.mjs" or
                 p.get_param("name", header="content-disposition") == "worker.mjs"]
        require(len(parts) == 1, "readback_module_missing_or_ambiguous")
        return parts[0]
    require("javascript" in content_type, "readback_content_type_unknown")
    return content


def leaks(data, values):
    """Literal grep for the first 12 bytes (or entire shorter value), no logging."""
    return any(v[:12].encode() in data for v in values if v)


def callback_code(path, host, expected_state):
    query = parse_qs(urlsplit(path).query, keep_blank_values=True)
    valid = (host == "127.0.0.1:8976" and urlsplit(path).path == "/callback" and
             len(query.get("state", [])) == 1 and
             hmac.compare_digest(query["state"][0].encode(), expected_state.encode()) and
             len(query.get("code", [])) == 1 and bool(query["code"][0]) and "error" not in query)
    return query["code"][0] if valid else None


@contextlib.contextmanager
def callback_stdin():
    # Read stdin itself, with terminal echo disabled so the code cannot enter a transcript.
    previous = None
    if sys.stdin.isatty():
        previous = termios.tcgetattr(sys.stdin.fileno())
        hidden = previous.copy()
        hidden[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSAFLUSH, hidden)
    try:
        yield
    finally:
        if previous is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSAFLUSH, previous)


class Capture(io.TextIOBase):
    def __init__(self, target):
        self.target, self.buffered = target, io.StringIO()

    def write(self, value):
        self.buffered.write(value)
        self.target.write(value)
        self.target.flush()
        return len(value)

    def flush(self):
        self.target.flush()


class Trial:
    def __init__(self, args, client=None):
        self.args = args
        self.started = time.monotonic()
        self.deadline = self.started + 600
        self.work_deadline = self.started + 420
        self.finishing = False
        self.client = client or httpx.Client(follow_redirects=False, trust_env=False, timeout=8)
        self.access = self.refresh = None
        self.sensitive = []
        self.tokens = []
        self.worker_attempted = self.app_attempted = False
        self.worker_owned = False
        self.app_ids = set()
        self.namespace_ids = set()
        self.account_read_baseline = False
        self.scopes_verified = False
        self.collisions_cleared = False
        self.existing_ids = {REUSE_APP}
        if args.reuse_existing_container_image:
            self.existing_ids.add(args.reuse_existing_container_image)
        self.path = f"/accounts/{args.account_id}/workers/scripts/aim-oauth-trial-{args.run_id}"
        self.apps = f"/accounts/{args.account_id}/containers/applications"
        self.namespaces = f"/accounts/{args.account_id}/workers/durable_objects/namespaces"
        self.name = "aim-oauth-trial-" + args.run_id
        self.ev = {"run_id": args.run_id, "account_id": args.account_id,
                   "dry_run": args.dry_run, "started_at": utc(), "steps": [],
                   "findings": {
                       "U1": {"status": "unproven", "image_ref": args.image or None,
                              "image_provenance": "operator_review_required" if args.image else
                              "existing_app_read_pending" if args.reuse_existing_container_image else
                              "not_in_pinned_catalog_build_or_template; template_uses_local_Dockerfile",
                              "public_image_distribution": "unproven_U1_open_for_sellers"},
                       "U2": {"status": "unproven", "requested_scopes": args.scopes,
                              "r2_binding_requested": bool(args.r2_bucket)},
                       "U4": {"status": "unproven"}, "U9": {"status": "unproven",
                              "public_visibility_domain_multiaccount_UX": "out_of_scope"}},
                   "residual_resources": []}

    def remember(self, value, token=False):
        if isinstance(value, str) and value:
            self.sensitive.append(value)
            if token:
                self.tokens.append(value)
        return value

    def request(self, step, method, path, oauth=False, **kwargs):
        require(not self.args.dry_run, "cloudflare_forbidden_in_dry_run")
        # No caller-supplied hosts, redirects, proxies, auth URLs or pagination links.
        if oauth:
            require(path in ("/token", "/revoke"), "oauth_endpoint_refused")
            url = OAUTH + path
        else:
            require(path.startswith(f"/accounts/{self.args.account_id}/"), "account_endpoint_refused")
            if method != "GET":
                self.guard_write(method, path, kwargs)
            url = API + path
            kwargs["headers"] = {**kwargs.get("headers", {}), "Authorization": "Bearer " + self.access}
        remaining = (self.deadline if self.finishing else self.work_deadline) - time.monotonic()
        require(remaining > 0.1, "deadline")
        start = time.monotonic()
        record = {"step": step, "at": utc(), "method": method,
                  "http_status": None, "cf_error_codes": []}
        self.ev["steps"].append(record)
        try:
            response = self.client.request(method, url, timeout=min(8, remaining),
                                           follow_redirects=False, **kwargs)
            record["http_status"] = response.status_code
            try:
                data = response.json()
            except ValueError:
                data = {}
            if isinstance(data, dict):
                record["cf_error_codes"] = [e["code"] for e in data.get("errors", [])
                                             if isinstance(e, dict) and isinstance(e.get("code"), int)]
            return response
        except BaseException as exc:
            record["failure"] = type(exc).__name__  # never str(exc), request/body/headers
            raise
        finally:
            record["elapsed_ms"] = round((time.monotonic() - start) * 1000)

    def guard_write(self, method, path, kwargs):
        require(self.scopes_verified and self.account_read_baseline and self.collisions_cleared,
                "write_preflight_incomplete")
        target = path + kwargs.get("json", {}).get("name", "")
        require(not any(name in target for name in DENIED_NAMES), "protected_resource")
        require(not any(identifier in path for identifier in self.existing_ids), "existing_resource_mutation")
        allowed = ((method == "PUT" and path == self.path and self.worker_attempted and not self.worker_owned) or
                   (method == "DELETE" and path == self.path and self.worker_attempted) or
                   (method == "POST" and path == self.apps and self.app_attempted and
                    kwargs.get("json", {}).get("name") == self.name) or
                   (method == "DELETE" and any(path == self.apps + "/" + i for i in self.app_ids)))
        require(allowed, "unowned_resource_mutation")

    def own_app(self, value):
        app_id = self.safe_id(value)
        require(app_id not in self.existing_ids, "existing_app_id_returned")
        self.app_ids.add(app_id)
        return app_id

    @staticmethod
    def ok(response):
        require(200 <= response.status_code < 300, "http_refusal")
        try:
            data = response.json()
        except ValueError:
            return None
        require(not isinstance(data, dict) or data.get("success") is not False, "api_refusal")
        return data.get("result", data) if isinstance(data, dict) else data

    def collection(self, step, path):
        # Paginate to exhaustion; never infer account/resource absence from page one.
        found = []
        for page in range(1, 101):
            response = self.request(step, "GET", path, params={"page": page, "per_page": 100})
            rows = self.ok(response)
            require(isinstance(rows, list), "collection_schema")
            found.extend(rows)
            info = response.json().get("result_info", {})
            if "total_pages" in info:
                if page >= info["total_pages"]:
                    return found
            elif len(rows) < 100:
                return found
        raise Refusal("pagination_bound")

    def fetch_bundle(self):
        start = time.monotonic()
        if self.args.artifact_file:
            bundle = Path(self.args.artifact_file).read_bytes()
            source = "local_copy_hash_verified"
        else:
            require(not self.args.dry_run, "offline_dry_run_requires_artifact_file")
            # Separate unauthenticated, fixed GitHub artifact host. Never reuse CF headers.
            response = self.client.get(ARTIFACT, follow_redirects=False, timeout=20)
            self.ev["steps"].append({"step": "artifact_fetch", "at": utc(),
                                      "http_status": response.status_code,
                                      "elapsed_ms": round((time.monotonic() - start) * 1000),
                                      "cf_error_codes": []})
            require(response.status_code == 200, "artifact_fetch_refused")
            bundle = response.content
            source = ARTIFACT
        actual = sha(bundle)
        self.ev["artifact"] = {"source": source, "canonical_url": ARTIFACT,
                               "sha256": actual, "verified": actual == BUNDLE_SHA,
                               "bytes": len(bundle)}
        require(actual == BUNDLE_SHA, "artifact_sha256_mismatch")
        return bundle

    def authorize(self):
        state = secrets.token_urlsafe(32)
        verifier = self.remember(secrets.token_urlsafe(64))
        trial = self

        class Callback(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.connection.settimeout(2)
                code = callback_code(self.path, self.headers.get("Host"), state)
                self.server.code = trial.remember(code)
                self.send_response(200 if code else 400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'")
                self.end_headers()
                self.wfile.write(b"<script>history.replaceState(null,'','/callback')</script>Close this tab.")

        class OneShotServer(HTTPServer):
            def handle_error(self, *_):
                pass  # no callback query, code, socket error or traceback logging

        # Exactly one HTTP request. Invalid state/path or cancellation consumes the attempt.
        with OneShotServer(("127.0.0.1", 8976), Callback) as server:
            server.timeout = min(360, max(0.1, self.work_deadline - time.monotonic() - 20))
            server.code = None
            print(authorize_url(self.args.client_id, state, verifier), flush=True)
            server.handle_request()
            require(server.code is not None, "callback_refused_or_timeout")
            self.ev["code_received"] = True
            self.exchange(server.code, verifier)

    def manual_authorize(self, directory):
        pkce = directory / "pkce.json"
        try:
            fd = os.open(pkce, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd) as stream:
                stat = os.fstat(stream.fileno())
                require(stat.st_uid == os.getuid() and stat.st_mode & 0o777 == 0o600,
                        "unsafe_pkce_file")
                require(0 <= time.time() - stat.st_mtime < 600, "pkce_expired")
                # Begin + finish together have at most ten minutes.
                remaining = 600 - (time.time() - stat.st_mtime)
                self.deadline = min(self.deadline, time.monotonic() + remaining)
                self.work_deadline = min(self.work_deadline, self.deadline - 180)
                signal.setitimer(signal.ITIMER_REAL, max(0.01, self.work_deadline - time.monotonic()))
                require(self.work_deadline > time.monotonic(), "pkce_work_window_expired")
                saved = json.load(stream)
            require(set(saved) == {"state", "verifier", "run_id"} and
                    saved["run_id"] == self.args.run_id and
                    all(isinstance(saved[k], str) and re.fullmatch(r"[A-Za-z0-9_-]{43,128}", saved[k])
                        for k in ("state", "verifier")), "pkce_schema")
            verifier = self.remember(saved["verifier"])
            # The callback is supplied only over stdin; never echo it or persist it.
            with callback_stdin():
                value = sys.stdin.readline(16385).rstrip("\r\n")
            require(len(value) <= 16384, "callback_too_long")
            code = self.remember(manual_code(value, saved["state"]))
            self.ev["code_received"] = True
            if self.args.dry_run:
                print('{"callback_validation": "PASS", "cloudflare_calls": 0, "exchange": "skipped"}')
            else:
                self.exchange(code, verifier, pkce)
        finally:
            pkce.unlink(missing_ok=True)

    def exchange(self, code, verifier, pkce=None):
        form = {"grant_type": "authorization_code", "client_id": self.args.client_id,
                "redirect_uri": REDIRECT, "code": code, "code_verifier": verifier}
        try:
            response = self.request("code_exchange", "POST", "/token", oauth=True, data=form)
        finally:
            # Remove single-use verifier before parsing/validating any response.
            if pkce is not None:
                pkce.unlink(missing_ok=True)
        data = response.json()
        self.access = self.remember(data.get("access_token"), token=True)
        self.refresh = self.remember(data.get("refresh_token"), token=True)
        self.ev["token"] = {"token_type": data.get("token_type"),
                            "expires_in": data.get("expires_in"),
                            "refresh_token_issued": bool(self.refresh),
                            "scope_field_present": "scope" in data,
                            "granted_scope": data.get("scope"), "received_at": utc()}
        self.ok(response)
        require(isinstance(self.access, str) and self.access, "access_token_missing")
        require(str(data.get("token_type", "")).lower() == "bearer", "token_type_refused")
        if "scope" not in data:
            self.ev["token"]["missing_scope_accepted"] = self.args.accept_missing_scope_field
            require(self.args.accept_missing_scope_field, "granted_scope_missing")
        else:
            require(isinstance(data["scope"], str) and set(data["scope"].split()) == set(SCOPES.split()),
                    "granted_scope_mismatch")
        require(isinstance(data.get("expires_in"), (int, float)) and data["expires_in"] > 0,
                "token_lifetime_missing")
        self.scopes_verified = True

    def install(self, bundle):
        scripts = self.collection("account_scoped_read", f"/accounts/{self.args.account_id}/workers/scripts")
        self.account_read_baseline = True
        self.ev["findings"]["U2"]["account_path_read"] = "pass"
        self.ev["findings"]["U2"]["foreign_account_negative_tests"] = "not_authorized_not_run"
        require(not any(w.get("id", w.get("name", "")).startswith(self.name) for w in scripts),
                "worker_name_collision")
        existing = self.request("worker_collision_check", "GET", self.path + "/settings")
        require(existing.status_code == 404 and 10007 in self.ev["steps"][-1]["cf_error_codes"],
                "worker_exists_or_absence_unproven")
        apps = self.collection("apps_before", self.apps)
        self.existing_ids.update(a["id"] for a in apps if isinstance(a.get("id"), str))
        require(not any(a.get("name", "").startswith(self.name) for a in apps), "app_name_collision")
        require(not any(n.get("script") == self.name for n in
                        self.collection("namespaces_before", self.namespaces)), "namespace_collision")
        self.collisions_cleared = True
        if self.args.reuse_existing_container_image:
            source_id = self.args.reuse_existing_container_image
            source = self.ok(self.request("existing_image_read", "GET", self.apps + "/" + source_id))
            image = source.get("configuration", {}).get("image")
            require(isinstance(image, str) and re.fullmatch(IMAGE_RE, image), "existing_image_not_digest_pinned")
            self.args.image = image
            self.ev["findings"]["U1"].update({"image_ref": image, "source_application_id": source_id,
                "image_provenance": "account_local_registry_path_only",
                "public_image_distribution": "unproven_U1_open_for_sellers"})
        require(bool(self.args.image), "missing_digest_image_U1")
        body, content_type = multipart(bundle, metadata(self.args.r2_bucket))
        # No write retries: PUT is an upsert API; preflight + unique run ID guard creation.
        self.worker_attempted = True
        self.ev["worker_create_attempted_at"] = utc()
        response = self.request("worker_upload", "PUT", self.path, content=body,
                                headers={"Content-Type": content_type})
        if self.args.r2_bucket and not 200 <= response.status_code < 300:
            # Preserve the API errors verbatim, except never persist a secret-bearing response.
            errors = response.json().get("errors", [])
            raw = json.dumps(errors).encode()
            require(not leaks(raw, self.sensitive), "secret_in_provider_error")
            self.ev["findings"]["U2"]["r2_errors_verbatim"] = errors
        self.ok(response)
        self.worker_owned = True
        self.readback(bundle)
        self.app_attempted = True
        self.ev["container_create_attempted_at"] = utc()
        app = self.ok(self.request("container_create", "POST", self.apps,
                                  json=self.app_body()))
        app_id = self.own_app(app["id"])
        self.ev["findings"]["U1"]["digest_accepted"] = True
        result = self.ok(self.request("container_readback", "GET", self.apps + "/" + app_id))
        require(result.get("configuration", {}).get("image") == self.args.image and
                result.get("scheduling_policy") == "default" and
                result.get("durable_objects", {}).get("namespace_id") in self.namespace_ids,
                "container_readback_mismatch")
        self.ev["findings"]["U1"]["status"] = "install_readback_pass_no_runtime_test"

    def app_body(self):
        return {"name": self.name, "scheduling_policy": "default", "instances": 0,
                "max_instances": 1,
                "configuration": {"image": self.args.image, "instance_type": "standard-2"},
                "durable_objects": {"namespace_id": next(iter(self.namespace_ids))}}

    @staticmethod
    def safe_id(value):
        require(isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9-]{16,64}", value),
                "resource_id_schema")
        return value

    def readback(self, bundle):
        content = self.request("worker_content_readback", "GET", self.path + "/content")
        self.ok(content)
        actual = sha(module_bytes(content.content, content.headers.get("Content-Type", "")))
        self.ev["readback"] = {"bundle_sha256": actual, "bundle_pass": actual == BUNDLE_SHA,
                               "bindings_pass": False, "settings_pass": False}
        settings = self.ok(self.request("worker_settings_readback", "GET", self.path + "/settings"))
        observed = settings.get("bindings", [])
        wanted = metadata(self.args.r2_bucket)
        require(len(observed) == len(wanted["bindings"]), "extra_or_missing_binding")
        namespaces = self.collection("namespace_readback", self.namespaces)
        for binding in wanted["bindings"]:
            matches = [b for b in observed if b.get("name") == binding["name"]]
            require(len(matches) == 1 and all(matches[0].get(k) == v for k, v in binding.items()),
                    "binding_readback_mismatch")
            if binding["type"] == "durable_object_namespace":
                ns_id = self.safe_id(matches[0].get("namespace_id"))
                require(any(n.get("id") == ns_id and n.get("script") == self.name and
                            n.get("class") == "CloudflareVerifier" and n.get("use_sqlite") is True
                            for n in namespaces), "sqlite_namespace_readback_mismatch")
                self.namespace_ids.add(ns_id)
        passed = (actual == sha(bundle) == BUNDLE_SHA and
                  settings.get("compatibility_date") == wanted["compatibility_date"] and
                  set(settings.get("compatibility_flags", [])) == set(wanted["compatibility_flags"]))
        self.ev["readback"].update({"bindings_pass": True, "settings_pass": passed,
                                     "namespace_ids": sorted(self.namespace_ids)})
        require(passed, "worker_readback_mismatch")
        self.ev["findings"]["U2"]["worker_upload_and_readback"] = "pass"

    def attempt(self, label, action):
        try:
            action()
            return True
        except BaseException as exc:
            self.ev.setdefault("failures", []).append({"phase": label,
                "reason": str(exc) if isinstance(exc, Refusal) else type(exc).__name__})
            return False

    def cleanup(self):
        # Reconcile timed-out creates by unique reserved name; do not blindly retry writes.
        if self.app_attempted:
            def reconcile_apps():
                for app in self.collection("cleanup_apps_reconcile", self.apps):
                    if app.get("name") == self.name:
                        self.own_app(app["id"])
            self.attempt("app_reconcile", reconcile_apps)
        for app_id in sorted(self.app_ids):
            def delete_app(app_id=app_id):
                self.ok(self.request("container_delete", "DELETE", self.apps + "/" + app_id))
                check = self.request("container_absent", "GET", self.apps + "/" + app_id)
                require(check.status_code == 404, "container_delete_unconfirmed")
            if not self.attempt("container_cleanup", delete_app):
                self.ev["residual_resources"].append({"container_application_id": app_id})
        if self.worker_attempted:
            def delete_worker():
                # Only the fresh reserved name passed preflight. No shared resource deletion.
                check = self.request("cleanup_worker_reconcile", "GET", self.path + "/settings")
                if check.status_code != 404:
                    self.ok(check)
                    self.ok(self.request("worker_delete_including_DO", "DELETE", self.path,
                                         params={"force": "true"}))
                absent = self.request("worker_absent", "GET", self.path + "/settings")
                require(absent.status_code == 404, "worker_delete_unconfirmed")
                remaining = self.collection("namespace_absence", self.namespaces)
                require(not any(n.get("script") == self.name or n.get("id") in self.namespace_ids
                                for n in remaining), "namespace_delete_unconfirmed")
            if not self.attempt("worker_cleanup", delete_worker):
                self.ev["residual_resources"].append({"worker": self.name,
                    "namespace_ids": sorted(self.namespace_ids)})
        if self.app_attempted:
            def apps_absent():
                require(not any(a.get("name") == self.name for a in
                                self.collection("apps_absence", self.apps)), "app_delete_unconfirmed")
            if not self.attempt("apps_absence", apps_absent):
                self.ev["residual_resources"].append({"container_application_name": self.name})

    def revoke_one(self, token, hint):
        form = {"client_id": self.args.client_id, "token": token, "token_type_hint": hint}
        self.ok(self.request("revoke_" + hint, "POST", "/revoke", oauth=True, data=form))

    def revoke(self):
        outcomes = []
        for token, hint in ((self.access, "access_token"), (self.refresh, "refresh_token")):
            if token:
                outcomes.append(self.attempt("revoke_" + hint, lambda t=token, h=hint: self.revoke_one(t, h)))
        if self.access:
            def denial():
                # Same GET successfully used before installation: no deleted-resource 404 shortcut.
                response = self.request("revoked_access_denial", "GET", f"/accounts/{self.args.account_id}/workers/scripts",
                                        params={"page": 1, "per_page": 100})
                require(response.status_code in (401, 403), "access_revocation_unproven")
                require(self.account_read_baseline, "revocation_read_baseline_missing")
            outcomes.append(self.attempt("revoked_access_denial", denial))
        if self.refresh:
            def renewal_denial():
                form = {"client_id": self.args.client_id, "grant_type": "refresh_token",
                        "refresh_token": self.refresh}
                response = self.request("revoked_refresh_denial", "POST", "/token", oauth=True, data=form)
                data = response.json()
                unexpected = []
                for key in ("access_token", "refresh_token"):
                    value = self.remember(data.get(key), token=True)
                    if value:
                        unexpected.append((value, key))
                for value, hint in unexpected:
                    self.attempt("unexpected_renewal_revoke", lambda v=value, h=hint: self.revoke_one(v, h))
                require(not unexpected and response.status_code in (400, 401, 403) and
                        data.get("error") == "invalid_grant", "refresh_revocation_unproven")
            outcomes.append(self.attempt("revoked_refresh_denial", renewal_denial))
        status = "pass" if outcomes and all(outcomes) else "unproven_or_failed"
        self.ev["findings"]["U4"]["revocation_and_denial"] = status
        self.ev["findings"]["U9"]["revocation_and_denial"] = status
        self.ev["findings"]["U4"]["status"] = "partial_local_trial_only"
        self.ev["findings"]["U9"]["status"] = "partial_private_client_only"


def arguments():
    p = argparse.ArgumentParser(description=__doc__)
    if sys.argv[1:2] == ["find-image"]:
        p.add_argument("command", choices=("find-image",))
        return p.parse_args()
    p.add_argument("command", nargs="?", choices=("run", "begin", "finish", "find-image"), default="run")
    p.add_argument("--manual-callback", action="store_true", help="Two-phase mode; run defaults to begin")
    p.add_argument("--accept-missing-scope-field", action="store_true", help="Explicitly accept omitted scope only")
    p.add_argument("--reuse-existing-container-image", nargs="?", const=REUSE_APP,
                   help="Read this existing app's pinned image; default ID when flag has no value")
    p.add_argument("--client-id", default=os.getenv("CF_OAUTH_CLIENT_ID"))
    p.add_argument("--account-id", default=os.getenv("CF_ACCOUNT_ID"))
    p.add_argument("--redirect-uri", default=os.getenv("CF_OAUTH_REDIRECT_URI", REDIRECT))
    p.add_argument("--scopes", default=os.getenv("CF_OAUTH_SCOPES", SCOPES))
    p.add_argument("--run-id", default=os.getenv("CF_OAUTH_RUN_ID"))
    p.add_argument("--r2-bucket", help="An EXISTING test bucket in the approved account; never created/read")
    p.add_argument("--image-ref", "--image", dest="image", help="Reviewed digest-pinned image reference")
    p.add_argument("--artifact-file", help="Hash-verified local worker.mjs; permits fully offline dry-run")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--self-test", action="store_true", help="Synthetic checks only; zero network")
    parsed = p.parse_args()
    require(parsed.command != "find-image", "find_image_accepts_no_options")
    return parsed


def validate(a):
    require(bool(a.client_id) and bool(re.fullmatch(r"[A-Za-z0-9._-]{1,200}", a.client_id)), "client_id_required")
    require(a.account_id == APPROVED_ACCOUNT, "account_not_approved")
    require(a.redirect_uri == REDIRECT, "redirect_mismatch")
    require(a.scopes == SCOPES, "scopes_mismatch")
    require(bool(a.run_id) and bool(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", a.run_id)), "invalid_run_id")
    require(not a.r2_bucket or bool(re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", a.r2_bucket)), "invalid_bucket")
    require(not a.image or bool(re.fullmatch(IMAGE_RE, a.image)), "digest_pinned_image_required")
    require(not (a.image and a.reuse_existing_container_image), "choose_one_image_source")
    if a.reuse_existing_container_image:
        Trial.safe_id(a.reuse_existing_container_image)


def private_write(directory, name, content):
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)


def prepare_directory(run_id):
    os.umask(0o077)
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not ROOT.is_symlink() and ROOT.stat().st_uid == os.getuid(), "unsafe_evidence_root")
    ROOT.chmod(0o700)
    directory = ROOT / run_id
    directory.mkdir(mode=0o700)  # atomic run-ID lock; refuse reuse, never overwrite evidence
    return directory


def begin(a):
    validate(a)
    directory = prepare_directory(a.run_id)
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    try:
        private_write(directory, "pkce.json", json.dumps({"state": state, "verifier": verifier,
                                                       "run_id": a.run_id}).encode())
        print(authorize_url(a.client_id, state, verifier), flush=True)
    except BaseException:
        (directory / "pkce.json").unlink(missing_ok=True)
        raise
    return 0


def finish_directory(run_id):
    require(bool(run_id) and bool(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", run_id)), "invalid_run_id")
    directory = ROOT / run_id
    require(not ROOT.is_symlink() and ROOT.stat().st_uid == os.getuid() and
            ROOT.stat().st_mode & 0o777 == 0o700 and
            not directory.is_symlink() and directory.is_dir() and directory.stat().st_uid == os.getuid() and directory.stat().st_mode & 0o777 == 0o700,
            "unsafe_run_directory")
    private_write(directory, "finish.lock", b"")  # one finish process, including failures
    return directory


def run(a):
    directory = finish_directory(a.run_id) if a.command == "finish" else None
    try:
        return run_prepared(a, directory)
    finally:
        if directory is not None:
            (directory / "pkce.json").unlink(missing_ok=True)


def run_prepared(a, directory):
    validate(a)
    directory = directory or prepare_directory(a.run_id)
    capture = Capture(sys.stdout)
    trial = Trial(a)
    # Suppress third-party request logging, core dumps and tracebacks containing locals.
    logging.disable(logging.CRITICAL)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def interrupted(*_):
        if trial.finishing:
            # The final alarm/cancel forbids any further network calls, even if an
            # individual cleanup attempt catches this exception to save evidence.
            trial.deadline = min(trial.deadline, time.monotonic())
        else:
            # socketserver may consume handler exceptions; the write gate must
            # still reject all main-work requests after a cancel/deadline.
            trial.work_deadline = min(trial.work_deadline, time.monotonic())
        raise Refusal("deadline_or_cancel")
    previous = {s: signal.signal(s, interrupted) for s in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)}
    signal.setitimer(signal.ITIMER_REAL, 420)
    success = False
    try:
        with contextlib.redirect_stdout(capture):
            try:
                require(not os.environ.pop("CF_OAUTH_CLIENT_SECRET", None), "token_auth_must_be_none")
                if a.command == "finish":
                    trial.manual_authorize(directory)
                bundle = trial.fetch_bundle()
                body, content_type = multipart(bundle, metadata(a.r2_bucket))
                trial.ev["multipart"] = {"bytes": len(body), "metadata": metadata(a.r2_bucket),
                                          "module_roundtrip_pass": module_bytes(body, content_type) == bundle}
                if a.dry_run:
                    print(json.dumps({"dry_run": "PASS", "bundle_sha256": sha(bundle),
                                      "bundle_bytes": len(bundle), "multipart_bytes": len(body),
                                      "cloudflare_calls": 0, "U1": "image_supplied_unproven" if a.image else
                                      "blocked_missing_public_image"}, sort_keys=True))
                else:
                    if a.command != "finish":
                        trial.authorize()
                    trial.install(bundle)
                success = True
            except BaseException as exc:
                trial.ev.setdefault("failures", []).append({"phase": "trial",
                    "reason": str(exc) if isinstance(exc, Refusal) else type(exc).__name__})
            finally:
                if a.command == "finish":
                    trial.attempt("pkce_delete", lambda: (directory / "pkce.json").unlink(missing_ok=True))
                trial.finishing = True
                signal.setitimer(signal.ITIMER_REAL, max(0.01, trial.deadline - time.monotonic() - 2))
                if not a.dry_run:
                    # Independent attempts: cleanup failures MUST NOT skip revocation.
                    trial.attempt("cleanup", trial.cleanup)
                    trial.attempt("revoke", trial.revoke)
                trial.ev["resource_manifest"] = {"worker_name": trial.name,
                    "worker_create_attempted": trial.worker_attempted,
                    "container_create_attempted": trial.app_attempted,
                    "container_application_ids": sorted(trial.app_ids),
                    "namespace_ids": sorted(trial.namespace_ids)}
                trial.ev["finished_at"] = utc()
                trial.ev["elapsed_seconds"] = round(time.monotonic() - trial.started, 3)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        trial.client.close()
    trial.ev["outcome"] = "dry_run_pass" if success and a.dry_run else (
        "trial_pass_with_documented_limits" if success and not trial.ev.get("failures") else "refused_or_failed")
    synthetic = "s1807_synthetic_canary_" + secrets.token_hex(16)
    trial.ev["token_canary"] = {"synthetic_evidence_detection": leaks(synthetic.encode(), [synthetic]),
                                "synthetic_stdout_detection": leaks(synthetic.encode(), [synthetic]),
                                "issued_tokens_checked": len(trial.tokens), "prefix_bytes": 12}
    stdout_bytes = capture.buffered.getvalue().encode()
    encoded = json.dumps(trial.ev, indent=2, sort_keys=True).encode() + b"\n"
    clean = not leaks(encoded + stdout_bytes, trial.sensitive)
    trial.ev["token_canary"]["evidence_and_stdout_pass"] = clean
    if not clean:
        # Never persist discovered secret bytes, even in a failed trial's evidence.
        trial.ev = {"run_id": a.run_id, "outcome": "secret_canary_failed",
                    "token_canary": {"evidence_and_stdout_pass": False},
                    "residual_resources": "inspect reserved run name in approved account"}
        stdout_bytes = b"[capture withheld: secret canary failed]\n"
    private_write(directory, "evidence.json", json.dumps(trial.ev, indent=2, sort_keys=True).encode() + b"\n")
    private_write(directory, "stdout.txt", stdout_bytes)
    # Scan the actual on-disk bytes as well as the in-memory candidate.
    require(not leaks((directory / "evidence.json").read_bytes() +
                      (directory / "stdout.txt").read_bytes(), trial.sensitive), "durable_canary_failed")
    trial.access = trial.refresh = None
    trial.sensitive.clear()
    trial.tokens.clear()
    return 0 if clean and success and not trial.ev.get("failures") else 1


def self_test():
    """In-file regression checks: all HTTP is synthetic MockTransport, never a socket."""
    import unittest

    class Checks(unittest.TestCase):
        def args(self, **overrides):
            values = dict(client_id="synthetic-client", account_id=APPROVED_ACCOUNT,
                          redirect_uri=REDIRECT, scopes=SCOPES, run_id="synthetic-test",
                          image=None, artifact_file=None, r2_bucket=None, dry_run=False, command="run",
                          manual_callback=False, accept_missing_scope_field=False, reuse_existing_container_image=None)
            return argparse.Namespace(**(values | overrides))

        def fixture(self, *, foreign=False, collision=False, upload_timeout=False,
                    revoke_failure=False, image=False, corrupt=False, account_status=200,
                    app_collision=False, worker_prefix_collision=False, reuse_image=None):
            state = {"worker": False, "app": False, "revoked": False, "calls": []}
            bundle = b"export default {}\n"
            ns_id, app_id = "a" * 32, "b" * 32
            def handler(req):
                state["calls"].append((req.method, req.url.host, req.url.path))
                path = req.url.path
                result, status = {}, 200
                if req.url.host == "dash.cloudflare.com":
                    if revoke_failure:
                        return httpx.Response(503, json={"error": "temporarily_unavailable"})
                    state["revoked"] = True
                    return httpx.Response(200, content=b"")
                if path.endswith("/workers/scripts"):
                    if state["revoked"]:
                        return httpx.Response(401, json={"errors": [{"code": 10000}]})
                    if account_status != 200:
                        return httpx.Response(account_status, json={"errors": [{"code": 10000}]})
                    result = [{"id": "aim-oauth-trial-synthetic-test-stale"}] if worker_prefix_collision else []
                    if foreign:
                        return httpx.Response(403, json={"errors": [{"code": 10000}]})
                elif "/containers/applications" in path:
                    app = {"id": app_id, "name": "aim-oauth-trial-synthetic-test",
                           "configuration": {"image": reuse_image or "docker.io/aim/verifier@sha256:" + "c" * 64},
                           "scheduling_policy": "default", "durable_objects": {"namespace_id": ns_id}}
                    if path.endswith(REUSE_APP):
                        self.assertEqual(req.method, "GET")
                        result = {"id": REUSE_APP, "name": "aim-cloudflare-verifier-cloudflareverifier",
                                  "configuration": {"image": reuse_image}}
                    elif req.method == "POST":
                        state["app"] = True
                        result = app
                    elif req.method == "DELETE":
                        state["app"] = False
                    elif path.endswith(app_id):
                        result, status = app, 200 if state["app"] else 404
                    else:
                        result = [app] if state["app"] else []
                        if app_collision:
                            result.append({"id": "d" * 32, "name": "aim-oauth-trial-synthetic-test-stale"})
                elif path.endswith("/namespaces"):
                    result = [{"id": ns_id, "script": "aim-oauth-trial-synthetic-test",
                               "class": "CloudflareVerifier", "use_sqlite": True}] if state["worker"] else []
                elif path.endswith("/settings"):
                    if collision or state["worker"]:
                        result = metadata()
                        result["bindings"][0]["namespace_id"] = ns_id
                    else:
                        return httpx.Response(404, json={"errors": [{"code": 10007}]})
                elif path.endswith("/content"):
                    body, mime = multipart(bundle + (b"corrupt" if corrupt else b""), metadata())
                    return httpx.Response(200, content=body, headers={"Content-Type": mime})
                elif req.method == "PUT":
                    state["worker"] = True
                    if upload_timeout:
                        raise httpx.ReadTimeout("synthetic private request text must never be logged")
                elif req.method == "DELETE":
                    state["worker"] = False
                else:
                    raise AssertionError("unexpected mock endpoint")
                return httpx.Response(status, json={"success": status == 200, "result": result})
            a = self.args(image="docker.io/aim/verifier@sha256:" + "c" * 64 if image else None,
                          reuse_existing_container_image=REUSE_APP if reuse_image else None)
            trial = Trial(a, httpx.Client(transport=httpx.MockTransport(handler)))
            trial.access = trial.remember(secrets.token_urlsafe(32), token=True)
            trial.scopes_verified = True
            return trial, state, bundle

        def test_pkce_callback_canary_and_mime(self):
            self.assertEqual(b64(hashlib.sha256(b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").digest()),
                             "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            self.assertEqual(callback_code("/callback?state=ok&code=secret", "127.0.0.1:8976", "ok"), "secret")
            for path in ("/callback?state=no&code=s", "/callback?state=ok&state=ok&code=s",
                         "/other?state=ok&code=s", "/callback?state=ok&code=s&error=denied"):
                self.assertIsNone(callback_code(path, "127.0.0.1:8976", "ok"))
            self.assertIsNone(callback_code("/callback?state=ok&code=s", "evil.test", "ok"))
            body, mime = multipart(b"exact\x00bytes\r\n", metadata("existing-test"))
            self.assertEqual(module_bytes(body, mime), b"exact\x00bytes\r\n")
            self.assertTrue(leaks(b"prefix synthetic_token_data suffix", ["synthetic_token_data"]))
            self.assertFalse(leaks(b"safe evidence", ["synthetic_token_data"]))

        def test_manual_callback_exact_url(self):
            good = REDIRECT + "?state=expected&code=synthetic-code"
            self.assertEqual(manual_code(good, "expected"), "synthetic-code")
            for bad in (good.replace("http:", "https:"), good.replace("127.0.0.1", "localhost"),
                        good.replace(":8976", ":8977"), good.replace(":8976", ""),
                        good.replace("/callback", "/callback/"), good + "#fragment",
                        good + "&state=expected", good + "&code=other", good + "&error=denied",
                        good.replace("127.0.0.1", "user@127.0.0.1"),
                        good.replace("state=expected", "state=wrong"), good + "\n"):
                with self.subTest(bad=bad), self.assertRaises(Refusal):
                    manual_code(bad, "expected")

        def test_scope_gate_and_retained_tokens(self):
            for scope, override, accepted in ((SCOPES, False, True),
                    ("containers.write workers-scripts.admin", False, True),
                    (None, False, False), (None, True, True),
                    ("containers.write", False, False), ("", True, False),
                    (SCOPES + " account-settings.read", True, False), (42, True, False)):
                with self.subTest(scope=scope, override=override):
                    calls = []
                    access = secrets.token_urlsafe(32)
                    def handler(req):
                        calls.append(req)
                        self.assertNotIn("authorization", req.headers)
                        self.assertNotIn("client_secret", parse_qs(req.content.decode()))
                        data = {"access_token": access, "token_type": "bearer", "expires_in": 3600}
                        if scope is not None:
                            data["scope"] = scope
                        return httpx.Response(200, json=data)
                    trial = Trial(self.args(accept_missing_scope_field=override),
                                  httpx.Client(transport=httpx.MockTransport(handler)))
                    if accepted:
                        trial.exchange("fake-code", "fake-verifier")
                        self.assertTrue(trial.scopes_verified)
                    else:
                        with self.assertRaises(Refusal):
                            trial.exchange("fake-code", "fake-verifier")
                        self.assertFalse(trial.scopes_verified)
                    self.assertEqual(trial.access, access)  # retained for finally revoke even on refusal
                    self.assertEqual(trial.ev["token"]["granted_scope"], scope)
                    self.assertEqual(trial.ev["token"]["scope_field_present"], scope is not None)
                    with self.assertRaises(Refusal):  # account/collision preflight still missing
                        trial.request("early_write", "PUT", trial.path)
                    self.assertEqual(len(calls), 1)

        def test_two_phase_single_use_and_failure_erasure(self):
            import tempfile
            from unittest.mock import patch
            for failure in (None, "state", "url", "expired", "exchange", "scope", "input"):
                with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                    events, calls = [], []
                    access, code = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                    a = self.args(command="finish")
                    directory = Path(tmp) / a.run_id
                    def handler(req):
                        calls.append(req.url.path)
                        self.assertTrue((directory / "pkce.json").exists())
                        form = parse_qs(req.content.decode())
                        self.assertEqual(form["code"], [code])
                        self.assertEqual(form["code_verifier"], [saved["verifier"]])
                        if failure == "exchange":
                            raise httpx.ReadTimeout("private data must not be logged")
                        return httpx.Response(200, json={"access_token": access, "token_type": "bearer",
                            "expires_in": 3600, "scope": "containers.write" if failure == "scope" else SCOPES})
                    def install(trial, bundle):
                        self.assertFalse((directory / "pkce.json").exists())
                        self.assertTrue(trial.scopes_verified)
                        events.append("install")
                    with patch(__name__ + ".ROOT", Path(tmp)), patch.dict(os.environ, {}, clear=True):
                        with contextlib.redirect_stdout(io.StringIO()) as output:
                            self.assertEqual(begin(a), 0)
                        self.assertEqual([x.name for x in directory.iterdir()], ["pkce.json"])
                        saved = json.loads((directory / "pkce.json").read_text())
                        self.assertEqual(set(saved), {"run_id", "state", "verifier"})
                        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                        self.assertEqual((directory / "pkce.json").stat().st_mode & 0o777, 0o600)
                        self.assertNotIn(saved["verifier"], output.getvalue())
                        callback = REDIRECT + "?" + urlencode({"state": "wrong" if failure == "state" else saved["state"],
                                                              "code": code})
                        if failure == "url":
                            callback = callback.replace("http:", "https:")
                        if failure == "expired":
                            os.utime(directory / "pkce.json", (time.time() - 601, time.time() - 601))
                        if failure == "input":
                            a.account_id = "f" * 32
                        trial = Trial(a, httpx.Client(transport=httpx.MockTransport(handler)))
                        with patch.object(sys, "stdin", io.StringIO(callback + "\n")), \
                             patch(__name__ + ".Trial", return_value=trial), \
                             patch.object(trial, "fetch_bundle", return_value=b"synthetic bundle"), \
                             patch.object(trial, "install", lambda bundle: install(trial, bundle)), \
                             patch.object(trial, "cleanup", lambda: events.append("cleanup")), \
                             patch.object(trial, "revoke", lambda: events.append("revoke")):
                            if failure == "input":
                                with self.assertRaises(Refusal):
                                    run(a)
                            else:
                                self.assertEqual(run(a), 0 if failure is None else 1)
                        self.assertFalse((directory / "pkce.json").exists())
                        self.assertEqual(events, [] if failure == "input" else
                                         ["install", "cleanup", "revoke"] if failure is None else ["cleanup", "revoke"])
                        if failure in ("state", "url", "expired", "input"):
                            self.assertEqual(calls, [])
                        if failure != "input":
                            evidence = (directory / "evidence.json").read_bytes() + (directory / "stdout.txt").read_bytes()
                            for secret in (code, access, saved["verifier"]):
                                self.assertNotIn(secret.encode(), evidence)
                        with self.assertRaises(FileExistsError):
                            finish_directory(a.run_id)

        def test_image_reuse_and_write_ownership(self):
            from unittest.mock import patch
            pinned = "registry.cloudflare.com/aim/aim-cloudflare-verifier@sha256:" + "c" * 64
            for image in (pinned, "registry.cloudflare.com/aim/verifier:latest"):
                trial, state, bundle = self.fixture(reuse_image=image)
                with patch(__name__ + ".BUNDLE_SHA", sha(bundle)):
                    if image == pinned:
                        trial.install(bundle)
                        self.assertEqual(trial.args.image, pinned)
                        self.assertEqual(trial.ev["findings"]["U1"]["image_provenance"], "account_local_registry_path_only")
                        trial.finishing = True
                        trial.cleanup()
                        trial.revoke()
                    else:
                        with self.assertRaises(Refusal):
                            trial.install(bundle)
                        self.assertFalse(any(method != "GET" for method, _, _ in state["calls"]))
                self.assertEqual([method for method, _, path in state["calls"] if REUSE_APP in path], ["GET"])
                self.assertFalse(state["worker"])
                self.assertFalse(state["app"])
            trial, state, _ = self.fixture(image=True)
            trial.account_read_baseline = trial.collisions_cleared = True
            for name in DENIED_NAMES:
                with self.assertRaisesRegex(Refusal, "protected_resource"):
                    trial.request("protected", "DELETE", trial.path.rsplit("/", 1)[0] + "/" + name)
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                with self.assertRaises(Refusal):
                    trial.request("existing", method, trial.apps + "/" + REUSE_APP)
                with self.assertRaises(Refusal):
                    trial.request("unknown", method, trial.apps + "/" + "e" * 32)
            with self.assertRaises(Refusal):
                trial.own_app(REUSE_APP)
            self.assertEqual(state["calls"], [])
            for image in ("docker.io/aim/verifier:latest", "docker.io/aim/verifier:tag@sha256:" + "c" * 64,
                          "docker.io/aim/verifier@sha256:1234"):
                with self.assertRaises(Refusal):
                    validate(self.args(image=image))

        def test_account_denial_and_prefix_collisions(self):
            for options in ({"account_status": 403}, {"account_status": 404},
                            {"app_collision": True}, {"worker_prefix_collision": True}):
                trial, state, bundle = self.fixture(image=True, **options)
                with self.assertRaises(Refusal):
                    trial.install(bundle)
                self.assertTrue(state["calls"])
                self.assertTrue(all(method == "GET" for method, _, _ in state["calls"]))
                self.assertFalse(any(path.endswith("/accounts") for _, _, path in state["calls"]))

        def test_input_and_dry_network_guards(self):
            for overrides in ({"account_id": "f" * 32}, {"run_id": "../escape"},
                              {"scopes": SCOPES + " workers-r2.write"},
                              {"redirect_uri": "http://evil.test"}, {"image": "mutable:latest"}):
                with self.assertRaises(Refusal):
                    validate(self.args(**overrides))
            trial, _, _ = self.fixture()
            trial.args.dry_run = True
            with self.assertRaises(Refusal):
                trial.request("forbidden", "GET", "/accounts")
            trial.args.dry_run = False
            with self.assertRaises(Refusal):
                trial.request("foreign", "GET", "/accounts/" + "f" * 32 + "/workers/scripts")

        def test_artifact_hash_and_redirect_refusals(self):
            for status, content in ((200, b"wrong bundle"), (302, b"")):
                seen = []
                def handler(req):
                    seen.append(req.url)
                    self.assertNotIn("authorization", req.headers)
                    return httpx.Response(status, content=content, headers={"Location": API})
                trial = Trial(self.args(), httpx.Client(transport=httpx.MockTransport(handler)))
                with self.assertRaises(Refusal):
                    trial.fetch_bundle()
                self.assertEqual([str(u) for u in seen], [ARTIFACT])

        def test_refresh_revocation_and_unexpected_renewal(self):
            for renewal_succeeds in (False, True):
                calls = []
                fake_access = secrets.token_urlsafe(32)
                fake_refresh = secrets.token_urlsafe(32)
                def handler(req):
                    calls.append((req.url.path, parse_qs(req.content.decode()) if req.content else {}))
                    if req.url.path.endswith("/revoke"):
                        return httpx.Response(200)
                    if req.url.path.endswith("/workers/scripts"):
                        return httpx.Response(403, json={"errors": [{"code": 10000}]})
                    if renewal_succeeds:
                        return httpx.Response(200, json={"access_token": fake_access,
                                                       "refresh_token": fake_refresh})
                    return httpx.Response(400, json={"error": "invalid_grant"})
                trial = Trial(self.args(), httpx.Client(transport=httpx.MockTransport(handler)))
                trial.access = trial.remember(secrets.token_urlsafe(32), token=True)
                trial.refresh = trial.remember(secrets.token_urlsafe(32), token=True)
                trial.account_read_baseline = True
                trial.finishing = True
                trial.revoke()
                self.assertEqual(calls[0][1]["token_type_hint"], ["access_token"])
                self.assertEqual(calls[1][1]["token_type_hint"], ["refresh_token"])
                self.assertEqual(len(calls), 6 if renewal_succeeds else 4)
                self.assertEqual(trial.ev["findings"]["U9"]["revocation_and_denial"],
                                 "unproven_or_failed" if renewal_succeeds else "pass")
                self.assertFalse(leaks(json.dumps(trial.ev).encode(), trial.sensitive))

        def test_finally_and_private_evidence(self):
            import tempfile
            from unittest.mock import patch
            events = []
            fake_access = secrets.token_urlsafe(32)
            def authorize(trial):
                trial.access = trial.remember(fake_access, token=True)
            def install(trial, bundle):
                raise Refusal("synthetic_install_refusal")
            def cleanup(trial):
                events.append("cleanup")
                raise Refusal("synthetic_cleanup_refusal")
            def revoke(trial):
                events.append("revoke")
            with tempfile.TemporaryDirectory() as tmp:
                with patch.dict(os.environ, {}, clear=True), patch(__name__ + ".ROOT", Path(tmp)), \
                     patch.object(Trial, "fetch_bundle", return_value=b"synthetic module"), \
                     patch.object(Trial, "authorize", authorize), patch.object(Trial, "install", install), \
                     patch.object(Trial, "cleanup", cleanup), patch.object(Trial, "revoke", revoke):
                    self.assertEqual(run(self.args()), 1)
                self.assertEqual(events, ["cleanup", "revoke"])
                directory = Path(tmp) / "synthetic-test"
                evidence = (directory / "evidence.json").read_bytes()
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                self.assertEqual((directory / "evidence.json").stat().st_mode & 0o777, 0o600)
                self.assertEqual((directory / "stdout.txt").stat().st_mode & 0o777, 0o600)
                self.assertNotIn(fake_access.encode(), evidence)
                self.assertTrue(json.loads(evidence)["token_canary"]["evidence_and_stdout_pass"])

        def test_refusals_cleanup_and_revocation(self):
            global BUNDLE_SHA
            saved = BUNDLE_SHA
            try:
                for options in ({}, {"foreign": True}, {"collision": True},
                                {"upload_timeout": True}, {"corrupt": True}, {"image": True},
                                {"revoke_failure": True}):
                    with self.subTest(options=options):
                        trial, state, bundle = self.fixture(**options)
                        BUNDLE_SHA = sha(bundle)  # synthetic test pin, restored below
                        trial.attempt("trial", lambda: trial.install(bundle))
                        trial.finishing = True
                        trial.cleanup()
                        trial.revoke()
                        mutations = [c for c in state["calls"] if c[0] in ("PUT", "POST", "DELETE")
                                     and c[1] == "api.cloudflare.com"]
                        if options.get("foreign") or options.get("collision"):
                            self.assertEqual(mutations, [])
                        else:
                            self.assertFalse(state["worker"])
                            self.assertFalse(state["app"])
                        self.assertTrue(any(c[2].endswith("/revoke") for c in state["calls"]))
                        revoke_index = next(i for i, c in enumerate(state["calls"]) if c[2].endswith("/revoke"))
                        self.assertTrue(all(c[0] == "GET" for c in state["calls"][revoke_index + 1:]))
                        evidence = json.dumps(trial.ev).encode()
                        self.assertFalse(leaks(evidence, trial.sensitive))
                        self.assertNotIn(b"synthetic private request text", evidence)
                        if options.get("revoke_failure"):
                            self.assertEqual(trial.ev["findings"]["U4"]["revocation_and_denial"], "unproven_or_failed")
            finally:
                BUNDLE_SHA = saved

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Checks)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    try:
        options = arguments()
        if getattr(options, "self_test", False):
            sys.exit(self_test())
        if options.command == "find-image":
            print("No credentials or network used. In finish, supply --reuse-existing-container-image " + REUSE_APP +
                  " to GET that existing app with the trial token and reuse its digest-pinned image. "
                  "This tests the account-local registry path only; public distribution U1 remains open. "
                  "Alternatively supply --image-ref REGISTRY/IMAGE@sha256:<64hex> after provenance review.")
            sys.exit(0)
        if options.command == "begin" or (options.command == "run" and options.manual_callback):
            sys.exit(begin(options))
        sys.exit(run(options))
    except Exception as exc:
        # All detailed API diagnostics are allowlisted in evidence; never show raw exceptions.
        print("trial refused: " + (str(exc) if isinstance(exc, Refusal) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
