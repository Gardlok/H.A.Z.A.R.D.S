// Rhaisour recipes compile inside a constrained Rhai engine.
//
// Registered HAZARDS capabilities will replace these descriptive values as
// the automation layer develops. There is deliberately no raw shell escape.

let workspace = #{
    name: "hazards",
    layout: "hazards",
    role: "development",
};

workspace.name + ":" + workspace.layout
