export function Empty({ title, hint }: { title: string; hint: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-border p-10 text-center">
      <p className="font-medium">{title}</p>
      <div className="mt-2 text-sm text-muted-foreground">{hint}</div>
    </div>
  );
}
