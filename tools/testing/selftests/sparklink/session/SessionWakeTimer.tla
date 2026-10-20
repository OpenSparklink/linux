(* SPDX-License-Identifier: GPL-2.0-only *)
-------------------------- MODULE SessionWakeTimer --------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Sessions, SkipTimerJoin
VARIABLES phase, owner, armed, callback, pending, running, notify,
          timerJoined, workJoined, refs
vars == <<phase, owner, armed, callback, pending, running, notify,
          timerJoined, workJoined, refs>>
Bit(x) == IF x THEN 1 ELSE 0
Init == /\ phase = [s \in Sessions |-> "open"]
        /\ owner = [s \in Sessions |-> TRUE]
        /\ armed = [s \in Sessions |-> FALSE]
        /\ callback = [s \in Sessions |-> "idle"]
        /\ pending = [s \in Sessions |-> FALSE]
        /\ running = [s \in Sessions |-> FALSE]
        /\ notify = [s \in Sessions |-> "idle"]
        /\ timerJoined = [s \in Sessions |-> FALSE]
        /\ workJoined = [s \in Sessions |-> FALSE]
        /\ refs = [s \in Sessions |-> 1]
Arm(s) == /\ phase[s] = "open" /\ ~armed[s]
          /\ armed' = [armed EXCEPT ![s] = TRUE]
          /\ UNCHANGED <<phase, owner, callback, pending, running, notify,
                         timerJoined, workJoined, refs>>
TimerBegin(s) == /\ armed[s] /\ callback[s] = "idle"
                /\ armed' = [armed EXCEPT ![s] = FALSE]
                /\ callback' = [callback EXCEPT ![s] = "hint"]
                /\ UNCHANGED <<phase, owner, pending, running, notify,
                               timerJoined, workJoined, refs>>
TimerHint(s) == /\ callback[s] = "hint"
               /\ callback' = [callback EXCEPT ![s] = "done"]
               /\ pending' = [pending EXCEPT ![s] = @ \/ phase[s] = "open"]
               /\ refs' = [refs EXCEPT ![s] = @ + Bit(phase[s] = "open" /\ ~pending[s])]
               /\ UNCHANGED <<phase, owner, armed, running, notify, timerJoined, workJoined>>
TimerDone(s) == /\ callback[s] = "done"
               /\ callback' = [callback EXCEPT ![s] = "idle"]
               /\ UNCHANGED <<phase, owner, armed, pending, running, notify,
                              timerJoined, workJoined, refs>>
NotifyBegin(s) == /\ phase[s] = "open" /\ notify[s] = "idle"
                 /\ notify' = [notify EXCEPT ![s] = "hint"]
                 /\ refs' = [refs EXCEPT ![s] = @ + 1]
                 /\ UNCHANGED <<phase, owner, armed, callback, pending, running,
                                timerJoined, workJoined>>
NotifyHint(s) == /\ notify[s] = "hint"
                /\ notify' = [notify EXCEPT ![s] = "done"]
                /\ pending' = [pending EXCEPT ![s] = @ \/ phase[s] = "open"]
                /\ refs' = [refs EXCEPT ![s] = @ + Bit(phase[s] = "open" /\ ~pending[s])]
                /\ UNCHANGED <<phase, owner, armed, callback, running, timerJoined, workJoined>>
NotifyDone(s) == /\ notify[s] = "done"
                /\ notify' = [notify EXCEPT ![s] = "idle"]
                /\ refs' = [refs EXCEPT ![s] = @ - 1]
                /\ UNCHANGED <<phase, owner, armed, callback, pending, running,
                               timerJoined, workJoined>>
StartWork(s) == /\ pending[s] /\ ~running[s]
               /\ pending' = [pending EXCEPT ![s] = FALSE]
               /\ running' = [running EXCEPT ![s] = TRUE]
               /\ UNCHANGED <<phase, owner, armed, callback, notify,
                              timerJoined, workJoined, refs>>
FinishWork(s) == /\ running[s]
                /\ running' = [running EXCEPT ![s] = FALSE]
                /\ refs' = [refs EXCEPT ![s] = @ - 1]
                /\ UNCHANGED <<phase, owner, armed, callback, pending, notify,
                               timerJoined, workJoined>>
Close(s) == /\ phase[s] = "open"
            /\ phase' = [phase EXCEPT ![s] = "closing"]
            /\ UNCHANGED <<owner, armed, callback, pending, running, notify,
                           timerJoined, workJoined, refs>>
JoinTimer(s) == /\ phase[s] = "closing" /\ ~timerJoined[s]
                /\ (SkipTimerJoin \/ callback[s] = "idle")
                /\ armed' = [armed EXCEPT ![s] = FALSE]
                /\ timerJoined' = [timerJoined EXCEPT ![s] = TRUE]
                /\ UNCHANGED <<phase, owner, callback, pending, running, notify,
                               workJoined, refs>>
JoinWork(s) == /\ phase[s] = "closing" /\ timerJoined[s]
               /\ ~workJoined[s] /\ ~running[s]
               /\ workJoined' = [workJoined EXCEPT ![s] = TRUE]
               /\ pending' = [pending EXCEPT ![s] = FALSE]
               /\ refs' = [refs EXCEPT ![s] = @ - Bit(pending[s])]
               /\ UNCHANGED <<phase, owner, armed, callback, running, notify, timerJoined>>
DropOwner(s) == /\ phase[s] = "closing" /\ timerJoined[s] /\ workJoined[s] /\ owner[s]
                /\ owner' = [owner EXCEPT ![s] = FALSE]
                /\ refs' = [refs EXCEPT ![s] = @ - 1]
                /\ UNCHANGED <<phase, armed, callback, pending, running, notify,
                               timerJoined, workJoined>>
Done == /\ \A s \in Sessions : refs[s] = 0
        /\ UNCHANGED vars
Next == (\E s \in Sessions : Arm(s) \/ TimerBegin(s) \/ TimerHint(s) \/ TimerDone(s)
          \/ NotifyBegin(s) \/ NotifyHint(s) \/ NotifyDone(s) \/ StartWork(s)
          \/ FinishWork(s) \/ Close(s) \/ JoinTimer(s) \/ JoinWork(s) \/ DropOwner(s)) \/ Done
Fair == \A s \in Sessions : WF_vars(TimerHint(s)) /\ WF_vars(TimerDone(s))
          /\ WF_vars(NotifyHint(s)) /\ WF_vars(NotifyDone(s)) /\ WF_vars(FinishWork(s))
          /\ WF_vars(JoinTimer(s)) /\ WF_vars(JoinWork(s)) /\ WF_vars(DropOwner(s))
Spec == Init /\ [][Next]_vars /\ Fair
TypeOK == /\ phase \in [Sessions -> {"open", "closing"}]
          /\ owner \in [Sessions -> BOOLEAN] /\ armed \in [Sessions -> BOOLEAN]
          /\ pending \in [Sessions -> BOOLEAN] /\ running \in [Sessions -> BOOLEAN]
          /\ timerJoined \in [Sessions -> BOOLEAN] /\ workJoined \in [Sessions -> BOOLEAN]
          /\ callback \in [Sessions -> {"idle", "hint", "done"}]
          /\ notify \in [Sessions -> {"idle", "hint", "done"}] /\ refs \in [Sessions -> 0..4]
ReferenceLedger == \A s \in Sessions : refs[s] = Bit(owner[s]) + Bit(pending[s]) + Bit(running[s]) + Bit(notify[s] # "idle")
NoFreeWhileLive == \A s \in Sessions : refs[s] = 0 => (~armed[s] /\ callback[s] = "idle" /\ ~pending[s] /\ ~running[s] /\ notify[s] = "idle")
TimerJoinedQuiescent == \A s \in Sessions : timerJoined[s] => (~armed[s] /\ callback[s] = "idle")
WorkJoinedQuiescent == \A s \in Sessions : workJoined[s] => (~pending[s] /\ ~running[s])
OwnerDropAfterJoins == \A s \in Sessions : ~owner[s] => (timerJoined[s] /\ workJoined[s] /\ phase[s] = "closing")
CleanupConverges == \A s \in Sessions : (phase[s] = "closing") ~> (refs[s] = 0)
=============================================================================
