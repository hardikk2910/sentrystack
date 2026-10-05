import { useAuth } from "../context/AuthContext";
import { useNavigate } from "react-router-dom";

export default function Dashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <div className="min-h-screen bg-slate-100">
      <nav className="bg-white border-b border-slate-200 px-6 py-4 flex items-center justify-between">
        <h1 className="text-lg font-semibold text-slate-900">SentryStack</h1>
        <div className="flex items-center gap-4">
          {user?.role === "admin" && (
            <button
              onClick={() => navigate("/admin/users")}
              className="text-sm font-medium text-slate-600 hover:text-slate-900 transition"
            >
              Admin
            </button>
          )}
          <button
            onClick={handleLogout}
            className="text-sm font-medium text-slate-600 hover:text-slate-900 transition"
          >
            Logout
          </button>
        </div>
      </nav>

      <main className="max-w-3xl mx-auto px-4 py-10">
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-8">
          <h2 className="text-xl font-semibold text-slate-900 mb-2">
            Welcome, {user?.username}
          </h2>
          <p className="text-sm text-slate-500">
            Role:{" "}
            <span className="font-medium text-slate-700">{user?.role}</span>
          </p>
        </div>
      </main>
    </div>
  );
}
