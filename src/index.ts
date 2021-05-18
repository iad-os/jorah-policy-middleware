import { RequestHandler, Request } from 'express';
import reduce from 'lodash.reduce';
import merge from 'lodash.merge';
import axiox from 'axios';
import { homedir } from 'os';

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

export type RequiredHandler = {
  [key: string]: (req: Request) => unknown;
};
export type OpaMiddlewareOptions = {
  doPost?: doPostHandler;
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
  return function opaMiddleware(options: OpaMiddlewareOptions): RequestHandler {
    const {
      required = {},
      toPolicyEvaluationRequest = toPolicyEvaluationRequestDefault,
      decisionPath = decisionPathDefault,
      onDecision = onDecisionDefault,
      doPost = doPostDefault,
    } = merge({}, defaults, options);
    return async function (req, res, next) {
      try {
        const requiredData = await fetchRequiredData(req, required);
        const opaRequest = toPolicyEvaluationRequest(req, requiredData);
        const policyPath = `${opa.url}${decisionPath(req)}`;
        const { data } = await doPost(req, policyPath, { input: opaRequest });
        const decisionLog = {
          allow: data.result?.allow,
          decision: {
            decision_path: policyPath,
            ...data.result,
          },
          request: opaRequest,
        };
        req.log.trace(decisionLog, `OPA-POLICY-${data.result?.allow ? 'OK' : 'KO'} - Request Access Control`);
        req.policyEvaluation = {
          decision: data as PolicyDecision,
          request: opaRequest,
          path: policyPath,
        };

        if (process.env.OPA_ADMISSION_CONTROL_DISABLED === 'true' || opa.dryRun.enabled) {
          onDecision(req, res, (err: unknown): void => {
            if (process.env.NODE_ENV === 'production')
              req.log.error({ rejected: !!err, decisionLog }, `|||---OPA-POLICY-ADMISSION-CONTROL-DISABLED---|||`);
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
      required: { [key: string]: (req: Request) => unknown }
    ): { [key: string]: unknown } {
      return reduce(
        required,
        (acc, reqFn, key) => {
          try {
            acc[key] = reqFn(req);
            return acc;
          } catch (err) {
            req.log.error({ req, err }, `KO OPA-MID--FETCH-DATA ${key}`);
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

const doPostDefault: doPostHandler = async (req, url, data, options) => {
  return await axiox.create().post(url, data, options);
};

const toPolicyEvaluationRequestDefault: ToPolicyEvaluationRequest = (req, required) => ({
  input: {
    ...required,
    req: {
      method: req.method,
      params: req.params,
    },
  },
});
