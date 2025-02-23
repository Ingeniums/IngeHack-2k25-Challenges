"use client";

import { useFormState } from "react-dom";
import { adminAction, userAction } from "./action";
import { useState } from "react";

export default function Form() {
  const [isAdmin, _] = useState(false);
  const [state, formAction] = useFormState(
    isAdmin ? adminAction : userAction,
    "Nothing"
  );

  return (
    <form
      action={formAction}
      className="flex flex-col items-center p-4 bg-gray-100 rounded shadow-md"
    >
      <button
        type="submit"
        className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-700"
      >
        Get your flag
      </button>
      <p className="mt-4 text-gray-700">{state}</p>
    </form>
  );
}
