import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Heading } from "../ui";
import { useUser } from "../user_context";
import { docByPath, docsForRole, docsGrouped } from "./catalog";
import { startWalkthrough } from "./Walkthrough";

export function Documentation() {
  const user = useUser();
  const articles = useMemo(() => docsForRole(user.role), [user.role]);
  const groups = useMemo(() => docsGrouped(user.role), [user.role]);
  const [params, setParams] = useSearchParams();
  const requested = params.get("page") || "";
  const selected = articles.find((article) => article.path === requested) || articles[0];

  function choose(path: string) {
    const next = new URLSearchParams(params);
    next.set("page", path);
    setParams(next, { replace: true });
  }

  return (
    <>
      <Heading
        kicker="Reference"
        title="Documentation"
        subtitle="What each page is for, how to configure it, how it works, and how to use it. The first-run walkthrough uses these same articles."
        actions={<button type="button" className="secondary" onClick={startWalkthrough}>Replay walkthrough</button>}
      />
      <div className="docs-layout">
        <nav className="card docs-index" aria-label="Documentation pages">
          {groups.map((entry) => (
            <section key={entry.group}>
              <h2>{entry.group}</h2>
              <ul>
                {entry.articles.map((article) => (
                  <li key={article.path}>
                    <button
                      type="button"
                      aria-current={selected?.path === article.path ? "page" : undefined}
                      onClick={() => choose(article.path)}
                    >
                      {article.title}
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </nav>
        {selected ? <Article path={selected.path} /> : null}
      </div>
    </>
  );
}

function Article({ path }: { path: string }) {
  const article = docByPath(path);
  if (!article) return null;
  return (
    <article className="card docs-article">
      <header className="section-head">
        <div>
          <span className="section-kicker">{article.group}</span>
          <h2>{article.title}</h2>
        </div>
        {article.path !== "/docs" ? <Link className="button secondary compact" to={article.path}>Open {article.title}</Link> : null}
      </header>
      <p>{article.summary}</p>
      <Section title="Features" items={article.features} />
      <Section title="How to configure" items={article.configure} />
      <Section title="How it works" items={article.works} />
      <Section title="How to use it" items={article.use} />
    </article>
  );
}

function Section({ title, items }: { title: string; items: readonly string[] }) {
  return (
    <section>
      <h3>{title}</h3>
      <ul>
        {items.map((item) => <li key={item}>{item}</li>)}
      </ul>
    </section>
  );
}
