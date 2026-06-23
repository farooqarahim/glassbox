/**
 * Record builders for the Glassbox interaction body.
 *
 * Mirrors the Rust `InteractionBody` shape; every optional field
 * uses `?:` so the JSON-serialized form drops missing keys in the
 * same byte order as the Rust `skip_serializing_if = "Option::is_none"`.
 *
 * NOTE: chain bytes are signed server-side by the Rust core — these
 * types are only the *body* that gets wrapped into a SignedRecord.
 */

export interface ContentRef {
  readonly hash_hex: string;
  readonly byte_size: number;
  readonly mime_type?: string;
}

export interface ModelFingerprint {
  readonly provider: string;
  readonly model_name: string;
  readonly model_version: string;
}

export interface DecisionContext {
  readonly decision_id: string;
  readonly outcome: string;
  readonly schema_uri?: string;
}

export interface HumanApproval {
  readonly approver_id: string;
  readonly decision: string;
  readonly decided_at: string;
  readonly note?: string;
}

export interface ToolInvocation {
  readonly tool_name: string;
  readonly args_hash_hex: string;
  readonly result_hash_hex: string;
}

export interface Tag {
  readonly key: string;
  readonly value: string;
}

export interface InteractionBody {
  readonly model?: ModelFingerprint;
  readonly input?: ContentRef;
  readonly output?: ContentRef;
  readonly decision?: DecisionContext;
  readonly approval?: HumanApproval;
  readonly tool_calls?: readonly ToolInvocation[];
  readonly tags?: readonly Tag[];
  readonly metadata?: Readonly<Record<string, string>>;
}

/**
 * Build an `InteractionBody`. Returns a frozen object; downstream
 * mutation is impossible (matches the immutability rule).
 */
export function buildInteraction(
  fields: Partial<InteractionBody> = {},
): Readonly<InteractionBody> {
  const known: ReadonlyArray<keyof InteractionBody> = [
    "model",
    "input",
    "output",
    "decision",
    "approval",
    "tool_calls",
    "tags",
    "metadata",
  ];
  for (const key of Object.keys(fields)) {
    if (!known.includes(key as keyof InteractionBody)) {
      throw new TypeError(`unknown InteractionBody field: ${key}`);
    }
  }
  const out: Record<string, unknown> = {};
  for (const k of known) {
    const v = fields[k];
    if (v !== undefined) out[k] = v;
  }
  return Object.freeze(out) as Readonly<InteractionBody>;
}
