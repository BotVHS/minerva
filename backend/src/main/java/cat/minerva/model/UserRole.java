package cat.minerva.model;

/**
 * Enum que defineix els diferents rols d'usuari en el sistema.
 *
 * RBAC (Role-Based Access Control):
 * - ADMIN: Accés total al sistema, pot crear/modificar usuaris, veure tots els logs
 * - SUPERVISOR: Pot supervisar operacions, veure logs però no modificar usuaris
 * - ANALISTA: Pot accedir a dades i fer anàlisis
 * - CONTRIBUIDOR: Accés bàsic, pot contribuir amb dades però amb permisos limitats
 *
 * Jerarquia de permisos: ADMIN > SUPERVISOR > ANALISTA > CONTRIBUIDOR
 */
public enum UserRole {
    /**
     * Administrador del sistema amb accés complet.
     * Pot crear usuaris, assignar rols, veure logs d'auditoria, etc.
     */
    ADMIN,

    /**
     * Supervisor amb accés a operacions de supervisió.
     * Pot veure logs i monitorar activitats però no modificar usuaris.
     */
    SUPERVISOR,

    /**
     * Analista amb accés a dades i eines d'anàlisi.
     * Accés limitat a les funcionalitats d'anàlisi.
     */
    ANALISTA,

    /**
     * Contribuidor amb accés bàsic.
     * Pot contribuir amb dades però amb permisos molt limitats.
     */
    CONTRIBUIDOR
}
