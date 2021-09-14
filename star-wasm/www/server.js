const Koa = require('koa');
const serve = require('koa-static');

(() => {
  const host = '0.0.0.0';
  const port = '8084';
  const app = new Koa();
  app.use(serve('./dist'));

  console.log(
    `Serving on http://${host}:${port}`,
  );
  app.listen(port, host);
})();
