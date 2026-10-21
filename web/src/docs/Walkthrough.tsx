import { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useUser } from "../user_context";
import { docsForRole, type PageDoc } from "./catalog";

const STORAGE_KEY = "black-onyx.walkthrough.v1";
export const WALKTHROUGH_EVENT = "blackonyx:walkthrough-start";

export function walkthroughFinished(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === "done";
  } catch {
    return false;
  }
}

export function finishWalkthrough() {
  try {
    localStorage.setItem(STORAGE_KEY, "done");
  } catch {
    /* storage unavailable; the tour can still be closed for this view */
  }
}

export function startWalkthrough() {
  window.dispatchEvent(new Event(WALKTHROUGH_EVENT));
}

function stepForPath(path: string, articles: readonly PageDoc[]): number {
  const exact = articles.findIndex((article) => article.path === path);
  if (exact >= 0) return exact;
  const nested = articles.findIndex((article) => article.path !== "/" && (path === article.path || path.startsWith(`${article.path}/`)));
  return nested >= 0 ? nested : 0;
}

export function Walkthrough() {
  const user = useUser();
  const location = useLocation();
  const navigate = useNavigate();
  const articles = useMemo(() => docsForRole(user.role), [user.role]);
  const [open, setOpen] = useState(() => !walkthroughFinished());
  const [index, setIndex] = useState(() => stepForPath(location.pathname, articles));
  const [follow, setFollow] = useState(false);

  useEffect(() => {
    const onStart = () => {
      setIndex(0);
      setFollow(true);
      setOpen(true);
    };
    window.addEventListener(WALKTHROUGH_EVENT, onStart);
    return () => window.removeEventListener(WALKTHROUGH_EVENT, onStart);
  }, []);

  useEffect(() => {
    if (!open || !follow) return;
    const article = articles[index];
    if (!article) return;
    if (location.pathname !== article.path) navigate(article.path);
  }, [open, follow, index, articles, location.pathname, navigate]);

  if (!open || articles.length === 0) return null;
  const article = articles[Math.min(index, articles.length - 1)];
  const last = index >= articles.length - 1;

  function close(done: boolean) {
    if (done) finishWalkthrough();
    setOpen(false);
    setFollow(false);
  }

  function go(nextIndex: number) {
    setFollow(true);
    setIndex(nextIndex);
  }

  return (
    <div className="walkthrough" role="dialog" aria-labelledby="walkthrough-title" aria-modal="false">
      <div className="section-head">
        <div>
          <span className="section-kicker">{article.group} · {index + 1} of {articles.length}</span>
          <h2 id="walkthrough-title">{article.title}</h2>
        </div>
        <button type="button" className="ghost compact" onClick={() => close(true)}>Skip</button>
      </div>
      <p>{article.summary}</p>
      <p><strong>How it works. </strong>{article.works[0]}</p>
      <p><strong>How to use it. </strong>{article.use[0]}</p>
      <div className="walkthrough-actions">
        <button type="button" className="secondary" onClick={() => go(index - 1)} disabled={index === 0}>Back</button>
        {last
          ? <button type="button" onClick={() => close(true)}>Finish</button>
          : <button type="button" onClick={() => go(index + 1)}>Next</button>}
      </div>
    </div>
  );
}
