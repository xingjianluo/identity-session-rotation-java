package com.github.xingjianluo.identitysessionrotationjava.session;

import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory session store. Lookup by id is atomic; account-wide revocation
 * visits every session currently indexed under that account.
 */
@Repository
public class SessionStore {

    private final ConcurrentMap<String, Session> sessionsById = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Set<String>> sessionIdsByAccount = new ConcurrentHashMap<>();

    public Session save(Session session) {
        sessionsById.put(session.id(), session);
        sessionIdsByAccount
                .computeIfAbsent(session.accountId(),
                        k -> Collections.newSetFromMap(new ConcurrentHashMap<>()))
                .add(session.id());
        return session;
    }

    public Optional<Session> findById(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessionsById.get(sessionId));
    }

    /**
     * Revokes a single active session. Idempotent: returns false (and keeps
     * the prior terminal reason) when the session is unknown or already in a
     * terminal state.
     */
    public boolean revokeOne(String sessionId, RevocationReason reason) {
        Session session = sessionId == null ? null : sessionsById.get(sessionId);
        if (session == null) {
            return false;
        }
        synchronized (session) {
            if (session.status() == SessionStatus.ACTIVE) {
                session.revoke(reason);
                return true;
            }
            return false;
        }
    }

    /**
     * Revokes every active session of an account with the given reason.
     * Revocation is idempotent: already revoked/expired sessions keep their
     * prior terminal state and reason. Returns only the sessions whose state
     * was changed by this call (for auditing).
     */
    public List<Session> revokeAllForAccount(String accountId, RevocationReason reason) {
        List<Session> revoked = new ArrayList<>();
        Set<String> ids = sessionIdsByAccount.get(accountId);
        if (ids == null) {
            return revoked;
        }
        for (String id : ids) {
            Session session = sessionsById.get(id);
            if (session != null && session.status() == SessionStatus.ACTIVE) {
                synchronized (session) {
                    if (session.status() == SessionStatus.ACTIVE) {
                        session.revoke(reason);
                        revoked.add(session);
                    }
                }
            }
        }
        return revoked;
    }
}
