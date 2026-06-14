export * as QuestionV2 from "./question"

import { Context, Deferred, Effect, Layer, Schema } from "effect"
import { EventV2 } from "./event"
import { Identifier } from "./id/id"
import { withStatics } from "./schema"
import { SessionSchema } from "./session/schema"

export const ID = Schema.String.check(Schema.isStartsWith("que")).pipe(
  Schema.brand("QuestionV2.ID"),
  withStatics((schema) => ({ ascending: (id?: string) => schema.make(Identifier.ascending("question", id)) })),
)
export type ID = typeof ID.Type

export const Option = Schema.Struct({
  label: Schema.String.annotate({ description: "展示文本（1-5 个词，保持简洁）" }),
  description: Schema.String.annotate({ description: "选项说明" }),
}).annotate({ identifier: "QuestionV2.Option" })
export type Option = typeof Option.Type

const base = {
  question: Schema.String.annotate({ description: "完整问题" }),
  header: Schema.String.annotate({ description: "非常短的标签（最多 30 个字符）" }),
  options: Schema.Array(Option).annotate({ description: "可选项" }),
  multiple: Schema.Boolean.pipe(Schema.optional).annotate({ description: "允许选择多个选项" }),
}

export const Info = Schema.Struct({
  ...base,
  custom: Schema.Boolean.pipe(Schema.optional).annotate({
    description: "允许输入自定义答案（默认 true）",
  }),
}).annotate({ identifier: "QuestionV2.Info" })
export type Info = typeof Info.Type

export const Prompt = Schema.Struct(base).annotate({ identifier: "QuestionV2.Prompt" })
export type Prompt = typeof Prompt.Type

export const Tool = Schema.Struct({
  messageID: Schema.String,
  callID: Schema.String,
}).annotate({ identifier: "QuestionV2.Tool" })
export type Tool = typeof Tool.Type

export const Request = Schema.Struct({
  id: ID,
  sessionID: SessionSchema.ID,
  questions: Schema.Array(Info).annotate({ description: "Questions to ask" }),
  tool: Tool.pipe(Schema.optional),
}).annotate({ identifier: "QuestionV2.Request" })
export type Request = typeof Request.Type

export const Answer = Schema.Array(Schema.String).annotate({ identifier: "QuestionV2.Answer" })
export type Answer = typeof Answer.Type

export const Reply = Schema.Struct({
  answers: Schema.Array(Answer).annotate({
    description: "用户按问题顺序给出的答案（每个答案都是已选 label 数组）",
  }),
}).annotate({ identifier: "QuestionV2.Reply" })
export type Reply = typeof Reply.Type

export const Event = {
  Asked: EventV2.define({ type: "question.v2.asked", schema: Request.fields }),
  Replied: EventV2.define({
    type: "question.v2.replied",
    schema: {
      sessionID: SessionSchema.ID,
      requestID: ID,
      answers: Schema.Array(Answer),
    },
  }),
  Rejected: EventV2.define({
    type: "question.v2.rejected",
    schema: {
      sessionID: SessionSchema.ID,
      requestID: ID,
    },
  }),
}

export class RejectedError extends Schema.TaggedErrorClass<RejectedError>()("QuestionV2.RejectedError", {}) {
  override get message() {
    return "The user dismissed this question"
  }
}

export class NotFoundError extends Schema.TaggedErrorClass<NotFoundError>()("QuestionV2.NotFoundError", {
  requestID: ID,
}) {}

export interface AskInput {
  readonly sessionID: SessionSchema.ID
  readonly questions: ReadonlyArray<Info>
  readonly tool?: Tool
}

export interface ReplyInput {
  readonly requestID: ID
  readonly answers: ReadonlyArray<Answer>
}

export interface Interface {
  readonly ask: (input: AskInput) => Effect.Effect<ReadonlyArray<Answer>, RejectedError>
  readonly reply: (input: ReplyInput) => Effect.Effect<void, NotFoundError>
  readonly reject: (requestID: ID) => Effect.Effect<void, NotFoundError>
  readonly list: () => Effect.Effect<ReadonlyArray<Request>>
}

export class Service extends Context.Service<Service, Interface>()("@openagent/v2/Question") {}

interface Pending {
  readonly request: Request
  readonly deferred: Deferred.Deferred<ReadonlyArray<Answer>, RejectedError>
}

/**
 * Location-owned pending prompts. The Location layer map must materialize this
 * layer once per embedded Location so replies cannot settle another Location's
 * deferred request.
 */
export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const events = yield* EventV2.Service
    const pending = new Map<ID, Pending>()

    yield* Effect.addFinalizer(() =>
      Effect.forEach(pending.values(), (item) => Deferred.fail(item.deferred, new RejectedError()), {
        discard: true,
      }).pipe(
        Effect.ensuring(
          Effect.sync(() => {
            pending.clear()
          }),
        ),
      ),
    )

    const ask = Effect.fn("QuestionV2.ask")((input: AskInput) =>
      Effect.uninterruptibleMask((restore) =>
        Effect.gen(function* () {
          const id = ID.ascending()
          const deferred = yield* Deferred.make<ReadonlyArray<Answer>, RejectedError>()
          const request: Request = { id, ...input }
          pending.set(id, { request, deferred })
          return yield* events.publish(Event.Asked, request).pipe(
            Effect.andThen(restore(Deferred.await(deferred))),
            Effect.ensuring(
              Effect.sync(() => {
                pending.delete(id)
              }),
            ),
          )
        }),
      ),
    )

    const reply = Effect.fn("QuestionV2.reply")((input: ReplyInput) =>
      Effect.uninterruptible(
        Effect.gen(function* () {
          const existing = pending.get(input.requestID)
          if (!existing) return yield* new NotFoundError({ requestID: input.requestID })
          yield* events.publish(Event.Replied, {
            sessionID: existing.request.sessionID,
            requestID: existing.request.id,
            answers: input.answers.map((answer) => [...answer]),
          })
          yield* Deferred.succeed(existing.deferred, input.answers)
          pending.delete(input.requestID)
        }),
      ),
    )

    const reject = Effect.fn("QuestionV2.reject")((requestID: ID) =>
      Effect.uninterruptible(
        Effect.gen(function* () {
          const existing = pending.get(requestID)
          if (!existing) return yield* new NotFoundError({ requestID })
          yield* events.publish(Event.Rejected, {
            sessionID: existing.request.sessionID,
            requestID: existing.request.id,
          })
          yield* Deferred.fail(existing.deferred, new RejectedError())
          pending.delete(requestID)
        }),
      ),
    )

    const list = Effect.fn("QuestionV2.list")(function* () {
      return Array.from(pending.values(), (item) => item.request)
    })

    return Service.of({ ask, reply, reject, list })
  }),
)

export const locationLayer = layer
