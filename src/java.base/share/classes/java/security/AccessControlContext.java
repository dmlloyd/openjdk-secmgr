/*
 * Copyright (c) 1997, 2015, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package java.security;

import java.net.URL;
import java.util.ArrayList;
import java.util.Objects;

import sun.security.util.Debug;
import sun.security.util.SecurityConstants;


/**
 * An AccessControlContext is used to make system resource access decisions
 * based on the context it encapsulates.
 *
 * <p>More specifically, it encapsulates a context and
 * has a single method, {@code checkPermission},
 * that is equivalent to the {@code checkPermission} method
 * in the AccessController class, with one difference: The AccessControlContext
 * {@code checkPermission} method makes access decisions based on the
 * context it encapsulates,
 * rather than that of the current execution thread.
 *
 * <p>Thus, the purpose of AccessControlContext is for those situations where
 * a security check that should be made within a given context
 * actually needs to be done from within a
 * <i>different</i> context (for example, from within a worker thread).
 *
 * <p> An AccessControlContext is created by calling the
 * {@code AccessController.getContext} method.
 * The {@code getContext} method takes a "snapshot"
 * of the current calling context, and places
 * it in an AccessControlContext object, which it returns. A sample call is
 * the following:
 *
 * <pre>
 *   AccessControlContext acc = AccessController.getContext()
 * </pre>
 *
 * <p>
 * Code within a different context can subsequently call the
 * {@code checkPermission} method on the
 * previously-saved AccessControlContext object. A sample call is the
 * following:
 *
 * <pre>
 *   acc.checkPermission(permission)
 * </pre>
 *
 * @see AccessController
 *
 * @since 1.2
 */

public final class AccessControlContext {

    static final ProtectionDomain[] NO_DOMAINS = new ProtectionDomain[0];
    private final AccessControlContext next;
    private final ProtectionDomain domain;
    private final int hashCode;
    private final DomainCombiner domainCombiner;

    private static boolean debugInit = false;
    private static Debug debug = null;

    static Debug getDebug()
    {
        if (debugInit)
            return debug;
        else {
            if (Policy.isSet()) {
                debug = Debug.getInstance("access");
                debugInit = true;
            }
            return debug;
        }
    }

    static final AccessControlContext ROOT_CONTEXT = new AccessControlContext(null, AccessController.Holder.ROOT_DOMAIN, false);

    /**
     * Create an AccessControlContext with the given array of ProtectionDomains.
     * Context must not be null. Duplicate domains will be removed from the
     * context.
     *
     * @param context the ProtectionDomains associated with this context.
     * The non-duplicate domains are copied from the array. Subsequent
     * changes to the array will not affect this AccessControlContext.
     * @throws NullPointerException if {@code context} is {@code null}
     * @deprecated Use {@link #with(ProtectionDomain)} or {@link #with(AccessControlContext)} instead.
     */
    @Deprecated
    public AccessControlContext(ProtectionDomain[] context)
    {
        domainCombiner = null;
        /*
         * In order to convert the array of PDs into a linked list, we have to iterate
         * by the last 2 items in the array.  We want to link to {@link #ROOT_DOMAIN} if
         * possible, but if we don't represent any actual additional domains then we will
         * end up essentially constructing a duplicate of it, so we don't want or need to
         * link to it.
         */
        final ProtectionDomain[] clone = context.clone();
        final int length = clone.length;
        ProtectionDomain domain;
        int i = 0;
        // find a current domain
        for (;;) {
            if (i == length) {
                // no domains found; make it a root
                this.next = null;
                this.domain = AccessController.Holder.ROOT_DOMAIN;
                hashCode = AccessController.Holder.ROOT_DOMAIN.hashCode();
                return;
            }
            domain = clone[i ++];
            if (domain != null && ! domainEquals(AccessController.Holder.ROOT_DOMAIN, domain)) {
                break;
            }
        }
        // now calculate build the parent chain
        AccessControlContext parent = ROOT_CONTEXT;
        ProtectionDomain next;
        for (;;) {
            if (i == length) {
                // all done
                this.next = parent;
                this.domain = domain;
                hashCode = parent.hashCode ^ domain.hashCode();
                return;
            }
            next = clone[i ++];
            if (next != null && ! domainEquals(AccessController.Holder.ROOT_DOMAIN, next)) {
                parent = parent.with(domain);
                domain = next;
            }
        }
    }

    /**
     * Create a new {@code AccessControlContext} with the given
     * {@code AccessControlContext} and {@code DomainCombiner}.
     * This constructor associates the provided
     * {@code DomainCombiner} with the provided
     * {@code AccessControlContext}.
     *
     * @param acc the {@code AccessControlContext} associated
     *          with the provided {@code DomainCombiner}.
     *
     * @param combiner the {@code DomainCombiner} to be associated
     *          with the provided {@code AccessControlContext}.
     *
     * @exception NullPointerException if the provided
     *          {@code context} is {@code null}.
     *
     * @exception SecurityException if a security manager is installed and the
     *          caller does not have the "createAccessControlContext"
     *          {@link SecurityPermission}
     * @since 1.3
     * @deprecated TODO
     */
    @Deprecated
    public AccessControlContext(AccessControlContext acc,
                                DomainCombiner combiner) {

        Objects.nonNull(acc);
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(SecurityConstants.CREATE_ACC_PERMISSION);
        }
        domain = acc.domain;
        next = acc;
        hashCode = acc.hashCode;
        domainCombiner = combiner;
    }

    AccessControlContext(final AccessControlContext next, final ProtectionDomain domain, final boolean preserveCombiner) {
        this.next = next;
        this.domain = domain;
        int hc = Objects.hashCode(domain);
        DomainCombiner combiner = null;
        if (next != null) {
            if (preserveCombiner) {
                combiner = next.domainCombiner;
            }
            hc ^= next.hashCode;
        }
        this.domainCombiner = combiner;
        this.hashCode = hc;
    }

    /**
     * Get the {@code DomainCombiner} associated with this
     * {@code AccessControlContext}.
     *
     * @return the {@code DomainCombiner} associated with this
     *          {@code AccessControlContext}, or {@code null}
     *          if there is none.
     *
     * @exception SecurityException if a security manager is installed and
     *          the caller does not have the "getDomainCombiner"
     *          {@link SecurityPermission}
     * @since 1.3
     * @deprecated TODO
     */
    @Deprecated
    public DomainCombiner getDomainCombiner() {

        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(SecurityConstants.GET_COMBINER_PERMISSION);
        }
        return domainCombiner;
    }

    /**
     * Determines whether the access request indicated by the
     * specified permission should be allowed or denied, based on
     * the security policy currently in effect, and the context in
     * this object. The request is allowed only if every ProtectionDomain
     * in the context implies the permission. Otherwise the request is
     * denied.
     *
     * <p>
     * This method quietly returns if the access request
     * is permitted, or throws a suitable AccessControlException otherwise.
     *
     * @param perm the requested permission.
     *
     * @exception AccessControlException if the specified permission
     * is not permitted, based on the current security policy and the
     * context encapsulated by this object.
     * @exception NullPointerException if the permission to check for is null.
     */
    public void checkPermission(Permission perm)
        throws AccessControlException
    {
        boolean dumpDebug = false;

        if (perm == null) {
            throw new NullPointerException("permission can't be null");
        }
        if (getDebug() != null) {
            // If "codebase" is not specified, we dump the info by default.
            dumpDebug = !Debug.isOn("codebase=");
            if (!dumpDebug) {
                // If "codebase" is specified, only dump if the specified code
                // value is in the stack.
                ProtectionDomain domain;
                for (AccessControlContext current = this; current != null; current = current.next) {
                    domain = current.domain;
                    final CodeSource codeSource = domain.getCodeSource();
                    if (codeSource != null) {
                        final URL location = codeSource.getLocation();
                        if (location != null) {
                            if (Debug.isOn("codebase=" + location.toString())) {
                                dumpDebug = true;
                                break;
                            }
                        }
                    }
                }
            }

            dumpDebug &= !Debug.isOn("permission=") ||
                Debug.isOn("permission=" + perm.getClass().getCanonicalName());

            if (dumpDebug && Debug.isOn("stack")) {
                Thread.dumpStack();
            }

            if (dumpDebug && Debug.isOn("domain")) {
                int i = 0;
                for (AccessControlContext current = this; current != null; current = current.next, i++) {
                    debug.println("domain " + i + " " + current.domain);
                }
            }
        }

        /*
         * iterate through the ProtectionDomains in the context.
         * Stop at the first one that doesn't allow the
         * requested permission (throwing an exception).
         *
         */

        for (AccessControlContext current = this; current != null; current = current.next) {
            final ProtectionDomain pd = current.domain;
            if (pd != null && ! pd.impliesWithAltFilePerm(perm)) {
                if (dumpDebug) {
                    debug.println("access denied " + perm);
                }

                if (Debug.isOn("failure") && debug != null) {
                    // Want to make sure this is always displayed for failure,
                    // but do not want to display again if already displayed
                    // above.
                    if (!dumpDebug) {
                        debug.println("access denied " + perm);
                    }
                    Thread.dumpStack();
                    final Debug db = debug;
                    AccessController.doPrivileged (new PrivilegedAction<>() {
                        public Void run() {
                            db.println("domain that failed "+pd);
                            return null;
                        }
                    });
                }
                throw new AccessControlException("access denied "+perm, perm);
            }
        }

        // allow if all of them allowed access
        if (dumpDebug) {
            debug.println("access allowed "+perm);
        }
    }

    /**
     * Get a new access control context which is the same as this one but adds the given protection domain.  This
     * is a privilege-reducing operation, as the resultant context is authorized for the intersection of this context's
     * permissions and the permissions of the given domain.  This context instance is returned if it already contains
     * the given protection domain.
     *
     * @param domain the protection domain to add
     * @return the new context, which might be the same as this context
     */
    public AccessControlContext with(ProtectionDomain domain) {
        return with(domain, false);
    }

    AccessControlContext with(ProtectionDomain domain, boolean preserveCombiner) {
        if (contains(domain)) {
            return this;
        }
        return new AccessControlContext(this, domain, preserveCombiner);
    }

    boolean contains(final ProtectionDomain domain) {
        if (domain == null || domainEquals(AccessController.Holder.ROOT_DOMAIN, domain)) {
            return true;
        }
        AccessControlContext acc = this;
        do {
            if (domainEquals(domain, acc.domain)) {
                return true;
            }
            acc = acc.next;
        } while (acc != null);
        return false;
    }

    /**
     * Get a new access control context which is the same as this one but adds all the given protection domains.  The
     * effect is the same as that of calling {@link #with(ProtectionDomain)} in a loop for each of the given domains.
     *
     * @param domains the protection domains to add
     * @return the new context, which might be the same as this context
     */
    public AccessControlContext withAll(final ProtectionDomain... domains) {
        AccessControlContext acc = this;
        if (domains != null) {
            for (ProtectionDomain domain : domains) {
                acc = acc.with(domain);
            }
        }
        return acc;
    }

    /**
     * Get a new access control context which is the intersection of this context and the given context.
     *
     * @param other the context to intersect with
     * @return the new context, which might be the same as this context
     */
    public AccessControlContext with(AccessControlContext other) {
        AccessControlContext acc = this;
        while (other != null) {
            acc = acc.with(other.domain);
            other = other.next;
        }
        return acc;
    }

    /**
     * Checks two AccessControlContext objects for equality.
     * Checks that {@code obj} is
     * an AccessControlContext and has the same set of ProtectionDomains
     * as this context.
     *
     * @param obj the object we are testing for equality with this object.
     * @return true if {@code obj} is an AccessControlContext, and has the
     * same set of ProtectionDomains as this context, false otherwise.
     */
    public boolean equals(Object obj) {
        return obj == this || obj instanceof AccessControlContext && equals((AccessControlContext) obj);
    }

    /*
     * Compare for equality.
     */
    private boolean equals(AccessControlContext that) {
        return this == that || hashCode == that.hashCode && this.containsAll(that) && that.containsAll(this);
    }

    private boolean containsAll(AccessControlContext other) {
        outer: for (AccessControlContext oc = other; oc != null; oc = oc.next) {
            for (AccessControlContext c = this; c != null; c = c.next) {
                if (oc == c) {
                    // The sublist of (oc...) is identical to the sublist of (c...)
                    // This means that all remaining PDs in other are contained in our list!
                    return true;
                }
                if (domainEquals(oc.domain, c.domain)) {
                    continue outer;
                }
            }
            // did not find oc.domain in our context.
            return false;
        }
        // every PD in other was found in our list.
        return true;
    }

    private static boolean domainEquals(final ProtectionDomain domain1, final ProtectionDomain domain2) {
        return domain1 == domain2 || domain1 != null && domain2 != null && domain1.getClass() == domain2.getClass() && domain1.equals(domain2);
    }

    /**
     * Returns the hash code value for this context. The hash code
     * is computed by exclusive or-ing the hash code of all the protection
     * domains in the context together.
     *
     * @return a hash code value for this context.
     */

    public int hashCode() {
        return hashCode;
    }

    ProtectionDomain getDomain() {
        return domain;
    }

    ProtectionDomain[] getProtectionDomains() {
        final ArrayList<ProtectionDomain> list = new ArrayList<>();
        for (AccessControlContext c = this; c != null; c = c.next) {
            list.add(c.domain);
        }
        return list.toArray(NO_DOMAINS);
    }
}
