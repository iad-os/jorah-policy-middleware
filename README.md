# JORAH Policy Middleware

### Add dependency to project

```sh
npm i @iad-os/jorah-policy-middleware
```

## Configure

```typescript
import jorah from '@iad-os/jorah-policy-middleware';

//...

const config = {
  url: 'http://opa:8181/v1/data',
  dryRun: {
    enabled: true,
    header: 'x-authorizer',
  },
};

const default = {
    doPost: async (req, url, data, options) => {
        return await axios.create().post(url, data, options);
    },
    onDecision: (req, res, next) => {
        if (req.policyEvaluation.decision?.result?.allow) {
            res.json(req.policyEvaluation);
            next();
            return;
        }
        next(new Error(`OPA-POLICY - FORBIDDEN`));
    },
    decisionPath: req => {
        return `/${req.path.split('/')[1]}`;
    },
    toPolicyEvaluationRequest: (req, required) => ({
        input: {
            ...required,
            req: {
            method: req.method,
            params: req.params,
            },
        },
    }),
};

export default jorah(config, default);
```

## Usage

On express router:

```typescript
import express from 'express';
import jorah from './jorah';

const router = express.Router();

router.route('/').all(
    // other middleware ...
    jorah({
        onDecision: (req, res, next) => {
            res.json(req.policyEvaluation);
        },
        decisionPath: req =>
            `${req.baseUrl}${reduce(req.params, (acc, param, name) => `${acc}/${name.replace('_id', '')}`, '')}`,
        required: {
            id: req => req.params.id
        },
    })
    // other middleware ...
);

export default router;

};
```

As express middleware:

```typescript
import express from 'express';
import jorah from './jorah';

const expressApp = express()
  // other middleware ...
  .use(jorah({})); // in this way the middleware use a default configurations
```
