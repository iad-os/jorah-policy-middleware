import axiox from 'axios';
import { Request, RequestHandler } from 'express';
import merge from 'lodash.merge';
import reduce from 'lodash.reduce';

export type PolicyEvaluation = {
  request: PolicyEvaluationRequest;
  decision: PolicyDecision;
  path?: string;
};

declare module 'http' {
  interface IncomingMessage {
    policyEvaluation: PolicyEvaluation;
  }
}

export interface PolicyDecision extends Record<string, unknown> {
  decision_id: string;
  result: { allow?: boolean; [key: string]: any };
}

export type PolicyEvaluationRequest = {
  input: {
    req: Partial<Request>;
  };
};

export type ToPolicyEvaluationRequest = (
  req: Request,
  required: {
    [key: string]: unknown;
  }
) => PolicyEvaluationRequest;

export type OnDecisionHandler = RequestHandler;

export type DecisionPath = (req: Request) => string;

export type doPostHandler = (
  req: Request,
  url: string,
  data: any,
  options?: {
    headers: Record<string, string>;
  }
) => Promise<{ data: any }>;

export type loggerHandler = (
  req: Request,
  level: 'info' | 'debug' | 'error' | 'trace' | 'warn',
  msg: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  payload?: any
) => void;

export type RequiredHandler = {
  [key: string]: (req: Request) => unknown;
};
export type OpaMiddlewareOptions = {
  doPost: doPostHandler;
  logger: loggerHandler;
  decisionPath?: DecisionPath;
  onDecision?: OnDecisionHandler;
  required?: RequiredHandler;
  toPolicyEvaluationRequest?: ToPolicyEvaluationRequest;
};

export type PolicyConfiguration = {
  url: string;
  dryRun: {
    enabled: boolean;
    header: string;
  };
};

export default function opaMiddlewareConfig(opa: PolicyConfiguration, defaults: OpaMiddlewareOptions) {
  return function opaMiddleware(options: Omit<OpaMiddlewareOptions, 'logger' | 'doPost'>): RequestHandler {
    const {
      required = {},
      toPolicyEvaluationRequest = toPolicyEvaluationRequestDefault,
      decisionPath = decisionPathDefault,
      onDecision = onDecisionDefault,
      doPost,
      logger,
    } = merge({}, defaults, options);
    return async function (req, res, next) {
      try {
        const requiredData = await fetchRequiredData(req, required, logger);
        const opaRequest = toPolicyEvaluationRequest(req, requiredData);
        const policyPath = `${opa.url}${decisionPath(req)}`;
        const { data } = await doPost(req, policyPath, opaRequest);
        const decisionLog = {
          allow: data.result?.allow,
          decision: {
            decision_path: policyPath,
            ...data.result,
          },
          request: opaRequest,
        };
        logger(req, 'trace', `OPA-POLICY-${data.result?.allow ? 'OK' : 'KO'} - Request Access Control`, decisionLog);
        req.policyEvaluation = {
          decision: data as PolicyDecision,
          request: opaRequest,
          path: policyPath,
        };

        if (process.env.OPA_ADMISSION_CONTROL_DISABLED === 'true' || opa.dryRun.enabled) {
          onDecision(req, res, (err: unknown): void => {
            if (process.env.NODE_ENV === 'production') {
              logger(req, 'error', `|||---OPA-POLICY-ADMISSION-CONTROL-DISABLED---|||`, {
                rejected: !!err,
                decisionLog,
              });
            }
            res.append(opa.dryRun.header, err ? 'reject' : 'allow');
            next();
          });
          return;
        }

        onDecision(req, res, next);
      } catch (err) {
        next(err);
      }
    };

    function fetchRequiredData(
      req: Request,
      required: { [key: string]: (req: Request) => unknown },
      logger: loggerHandler
    ): { [key: string]: unknown } {
      return reduce(
        required,
        (acc, reqFn, key) => {
          try {
            acc[key] = reqFn(req);
            return acc;
          } catch (err) {
            logger(req, 'error', `KO OPA-MID--FETCH-DATA ${key}`, { req, err });
            acc[key] = undefined;
            return acc;
          }
        },
        {} as Record<string, unknown>
      );
    }
  };
}
function onDecisionDefault(): OnDecisionHandler {
  return ({ policyEvaluation }, res, next) => {
    const { decision } = policyEvaluation;
    decision?.allow ? next() : next(new Error(`OPA-POLICY - FORBIDDEN`));
  };
}

function decisionPathDefault(): DecisionPath {
  return req => `${req.baseUrl}${reduce(req.params, (acc, param, name) => `${acc}/${name.replace('_id', '')}`, '')}`;
}

const toPolicyEvaluationRequestDefault: ToPolicyEvaluationRequest = (req, required) => ({
  input: {
    ...required,
    req: {
      method: req.method,
      params: req.params,
    },
  },
});
