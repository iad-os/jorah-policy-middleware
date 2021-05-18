import { RequestHandler, Request, NextFunction } from 'express';
import reduce from 'lodash.reduce';
import merge from 'lodash.merge';

export type ToPolicyEvaluationRequest = (
  req: Request,
  required: {
    [key: string]: unknown;
  }
) => any;

export type OnDecisionHandler = (decision: Record<string, unknown>, next: NextFunction) => void;

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
  doPost: doPostHandler;
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
    } = merge({}, defaults, options);
    return async function (req, res, next) {
      try {
        const requiredData = await fetchRequiredData(req, required);
        const opaRequest = toPolicyEvaluationRequest(req, requiredData);
        const policyPath = `${opa.url}${decisionPath(req)}`;
        const { data } = await options.doPost(req, policyPath, { input: opaRequest });
        const decisionLog = {
          allow: data.result?.allow,
          decision: {
            decision_path: policyPath,
            ...data.result,
          },
          request: opaRequest,
        };
        req.log.trace(decisionLog, `OPA-POLICY-${data.result?.allow ? 'OK' : 'KO'} - Request Access Control`);
        if (process.env.OPA_ADMISSION_CONTROL_DISABLED === 'true' || opa.dryRun.enabled) {
          onDecision(data.result, (err: unknown): void => {
            if (process.env.NODE_ENV === 'production')
              req.log.error({ rejected: !!err, decisionLog }, `|||---OPA-POLICY-ADMISSION-CONTROL-DISABLED---|||`);
            res.append(opa.dryRun.header, err ? 'reject' : 'allow');
            next();
          });
          return;
        }
        onDecision(data.result, next);
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
  return (decision, next) => {
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
