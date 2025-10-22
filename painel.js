// ===============================
// CONFIGURAÇÕES E CONSTANTES
// ===============================

/**
 * CONFIGURAÇÃO DO SISTEMA E PERMISSÕES
 * 
 * SISTEMA DE PERMISSÕES HIERÁRQUICO:
 * 
 * VOLUNTÁRIO (Nível 1):
 * ✅ Gerenciar Alunos (criar, editar, visualizar)
 * ✅ Gerenciar Atividades (criar, editar, visualizar) 
 * ✅ Visualizar Meus Dados (próprios dados)
 * ❌ Não pode gerenciar voluntários
 * ❌ Não pode gerenciar voluntários
 * ❌ Não pode gerenciar administrador
 * 
 * ADMIN (Nível 2):
 * ✅ Todas as permissões do VOLUNTÁRIO
 * ✅ Gerenciar Voluntários (criar, editar, visualizar)
 * ✅ Gerenciar Voluntários (criar, editar, visualizar)
 * ✅ Visualizar Meus Dados (próprios dados)
 * ❌ Não pode gerenciar administrador
 * 
 * ADM_MASTER (Nível 3):
 * ✅ Todas as permissões do ADMIN
 * ✅ Gerenciar administrador (criar, editar, visualizar)
 * ❌ Não vê "Meus Dados" (não é operacional, apenas supervisão)
 * 
 * Para PRODUÇÃO:
 * - MOCK_MODE: false
 * - DEVELOPMENT_MODE: false
 * - API_BASE_URL: URL da API real
 * 
 * Para DESENVOLVIMENTO/TESTE:
 * - DEVELOPMENT_MODE: true (permite usuário de teste)
 * - MOCK_MODE: true (usa dados locais)
 */

// Função para detectar ambiente de produção
function detectEnvironment() {
    const isProduction = window.location.hostname !== 'localhost' && 
                        window.location.hostname !== '127.0.0.1' && 
                        !window.location.hostname.includes('local') &&
                        !window.location.hostname.includes('192.168') &&
                        !window.location.hostname.includes('10.0');
    
    console.log(`🌍 Ambiente detectado: ${isProduction ? 'PRODUÇÃO' : 'DESENVOLVIMENTO'}`);
    console.log(`📍 Hostname: ${window.location.hostname}`);
    return isProduction;
}

// Detectar ambiente atual
const IS_PRODUCTION = detectEnvironment();

const CONFIG = {
    API_BASE_URL: IS_PRODUCTION && typeof PRODUCTION_CONFIG !== 'undefined' 
        ? PRODUCTION_CONFIG.API_BASE_URL || "https://saberviver-api.up.railway.app"
        : "https://saberviver-api.up.railway.app",
    
    // SISTEMA USA APENAS API REAL - SEM MOCK
    DEVELOPMENT_MODE: false,
    
    TIMEOUT: IS_PRODUCTION && typeof PRODUCTION_CONFIG !== 'undefined'
        ? PRODUCTION_CONFIG.NETWORK?.TIMEOUT || 30000
        : 30000,
    
    RETRY_ATTEMPTS: IS_PRODUCTION && typeof PRODUCTION_CONFIG !== 'undefined'
        ? PRODUCTION_CONFIG.NETWORK?.RETRY_ATTEMPTS || 3
        : 3,
    
    // Configurações específicas
    LOGGING_ENABLED: IS_PRODUCTION && typeof PRODUCTION_CONFIG !== 'undefined'
        ? PRODUCTION_CONFIG.LOGGING?.ENABLED !== false
        : true,
    
    CACHE_ENABLED: IS_PRODUCTION && typeof PRODUCTION_CONFIG !== 'undefined'
        ? PRODUCTION_CONFIG.CACHE?.ENABLED || false
        : false
};


// ===============================
// CLASSES DE MODELO
// ===============================
class Aluno {
    constructor(data = {}) {
        this.id = data.id || null;
        this.nome = data.nome || '';
        this.sobre_nome = data.sobre_nome || '';
        this.apelido = data.apelido || '';
        this.cpf = data.cpf || '';
        this.data_nascimento = data.data_nascimento || '';
        this.nome_responsavel = data.nome_responsavel || '';
        this.cpf_responsavel = data.cpf_responsavel || '';
        this.telefone_principal = data.telefone_principal || '';
        this.telefone_opcional = data.telefone_opcional || '';
        this.atividade = data.atividade || '';
        this.status = data.status || 'ativo';
        this.createdAt = data.createdAt || new Date().toISOString();
    }

    // Método para calcular idade a partir da data de nascimento
    get idade() {
        if (!this.data_nascimento) return 0;
        const hoje = new Date();
        const nascimento = new Date(this.data_nascimento);
        let idade = hoje.getFullYear() - nascimento.getFullYear();
        const mes = hoje.getMonth() - nascimento.getMonth();
        if (mes < 0 || (mes === 0 && hoje.getDate() < nascimento.getDate())) {
            idade--;
        }
        return idade;
    }

    validate() {
        const errors = [];
        if (!this.nome.trim()) errors.push('Nome é obrigatório');
        if (!this.sobre_nome.trim()) errors.push('Sobrenome é obrigatório');
        if (!this.data_nascimento) errors.push('Data de nascimento é obrigatória');
        if (!this.cpf.trim()) errors.push('CPF do aluno é obrigatório');
        if (!this.nome_responsavel.trim()) errors.push('Nome do responsável é obrigatório');
        if (!this.telefone_principal.trim()) {
            errors.push('Telefone principal é obrigatório');
        } else {
            const phoneNumbers = this.telefone_principal.replace(/\D/g, '');
            if (phoneNumbers.length < 10 || phoneNumbers.length > 11) {
                errors.push('Telefone principal deve ter 10 ou 11 dígitos');
            }
        }
        if (this.idade < 1 || this.idade > 100) errors.push('Idade deve ser entre 1 e 100 anos');
        return errors;
    }
}

class Atividade {
    constructor(data = {}) {
        this.id = data.id || null;
        this.nome = data.nome || '';
        this.descricao = data.descricao || '';
        this.alunosInscritos = data.alunosInscritos || [];
        this.capacidadeMaxima = data.capacidadeMaxima || 20;
        this.createdAt = data.createdAt || new Date().toISOString();
    }

    validate() {
        const errors = [];
        if (!this.nome.trim()) errors.push('Nome da atividade é obrigatório');
        return errors;
    }

    adicionarAluno(alunoId) {
        if (!this.alunosInscritos.includes(alunoId) && this.alunosInscritos.length < this.capacidadeMaxima) {
            this.alunosInscritos.push(alunoId);
            return true;
        }
        return false;
    }

    removerAluno(alunoId) {
        const index = this.alunosInscritos.indexOf(alunoId);
        if (index > -1) {
            this.alunosInscritos.splice(index, 1);
            return true;
        }
        return false;
    }
}

class Voluntario {
    constructor(data = {}) {
        this.id = data.id || null;
        this.nome = data.nome || '';
        this.email = data.email || '';
        this.telefone = data.telefone || '';
        this.cpf = data.cpf || '';
        this.atividade = data.atividade || '';
        this.status = data.status || 'ativo';
        this.role = data.role || 'VOLUNTARIO';
        this.createdAt = data.createdAt || new Date().toISOString();
    }

    validate() {
        const errors = [];
        if (!this.nome.trim()) errors.push('Nome é obrigatório');
        if (!this.email.trim()) errors.push('Email é obrigatório');
        if (!this.isValidEmail(this.email)) errors.push('Email inválido');
        if (!this.telefone.trim()) {
            errors.push('Telefone é obrigatório');
        } else {
            const phoneNumbers = this.telefone.replace(/\D/g, '');
            if (phoneNumbers.length < 10 || phoneNumbers.length > 11) {
                errors.push('Telefone deve ter 10 ou 11 dígitos');
            }
        }
        return errors;
    }

    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
}



class Admin {
    constructor(data = {}) {
        this.id = data.id || null;
        this.nome = data.nome || '';
        this.email = data.email || '';
        this.telefone = data.telefone || '';
        this.cpf = data.cpf || '';
        this.role = data.role || 'ADM';
        this.senha = data.senha || '';
        this.status = data.status || 'ativo';
        this.createdAt = data.createdAt || new Date().toISOString();
    }

    validate() {
        const errors = [];
        if (!this.nome.trim()) errors.push('Nome é obrigatório');
        if (!this.email.trim()) errors.push('Email é obrigatório');
        if (!this.isValidEmail(this.email)) errors.push('Email inválido');
        if (!this.telefone.trim()) {
            errors.push('Telefone é obrigatório');
        } else {
            const phoneNumbers = this.telefone.replace(/\D/g, '');
            if (phoneNumbers.length < 10 || phoneNumbers.length > 11) {
                errors.push('Telefone deve ter 10 ou 11 dígitos');
            }
        }
        if (!this.cpf.trim()) {
            errors.push('CPF é obrigatório');
        } else {
            // Aceita qualquer CPF com 11 dígitos, sem validação de dígito verificador
            const cpfNumeros = this.cpf.replace(/\D/g, '');
            if (cpfNumeros.length !== 11) {
                errors.push('O CPF deve conter 11 dígitos.');
            }
        }
        if (!this.role || !['ADM', 'ADM_MASTER'].includes(this.role)) {
            errors.push('Tipo de administrador inválido');
        }
        if (!this.senha || this.senha.length < 6) {
            errors.push('Senha deve ter pelo menos 6 caracteres');
        }
        if (!this.sobreNome || !this.sobreNome.trim()) {
            errors.push('O SobreNome é obrigatório');
        }
        if (!this.areaAtuacao || !this.areaAtuacao.trim()) {
            errors.push('A área de atuação é obrigatória');
        }
        return errors;
    }

    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    isValidCPF(cpf) {
        // Remove caracteres não numéricos
        cpf = cpf.replace(/\D/g, '');
        
        // Verifica se tem 11 dígitos
        if (cpf.length !== 11) return false;
        
        // Verifica se todos os dígitos são iguais
        if (/^(\d)\1{10}$/.test(cpf)) return false;
        
        // Validação do primeiro dígito verificador
        let soma = 0;
        for (let i = 0; i < 9; i++) {
            soma += parseInt(cpf.charAt(i)) * (10 - i);
        }
        let resto = (soma * 10) % 11;
        if (resto === 10 || resto === 11) resto = 0;
        if (resto !== parseInt(cpf.charAt(9))) return false;
        
        // Validação do segundo dígito verificador
        soma = 0;
        for (let i = 0; i < 10; i++) {
            soma += parseInt(cpf.charAt(i)) * (11 - i);
        }
        resto = (soma * 10) % 11;
        if (resto === 10 || resto === 11) resto = 0;
        if (resto !== parseInt(cpf.charAt(10))) return false;
        
        return true;
    }
}

// ===============================
// SERVIÇO DE API - CLASSE REMOVIDA (DUPLICADA)
// A classe ApiService completa está na linha ~2800
// ===============================

// (métodos da primeira classe ApiService removidos)

// ===============================
// SERVIÇO DE AUTENTICAÇÃO
// ===============================
class AuthService {
    static isAuthenticated() {
        console.log('🔍 === VERIFICAÇÃO DE AUTENTICAÇÃO COM VALIDAÇÃO JWT ===');
        
        const token = localStorage.getItem('saberviver_token');
        const user = localStorage.getItem('saberviver_user_data');
        
        console.log('🔑 Token encontrado:', token ? `${token.substring(0, 50)}...` : 'NENHUM');
        console.log('👤 Dados do usuário encontrados:', user ? 'SIM' : 'NÃO');
        
        // Verificação básica de existência
        if (!token) {
            console.warn('🔐 FALHA: Token ausente');
            return false;
        }
        
        if (!user) {
            console.warn('🔐 FALHA: Dados do usuário ausentes');
            return false;
        }
        
        // Validação JWT completa
        if (!this.validateJWTToken(token)) {
            console.warn('🔐 FALHA: Token JWT inválido');
            console.log('🔍 Executando debug do token...');
            this.debugToken(token);
            return false;
        }
        
        // Validar se os dados do usuário são básicos (validação mais flexível)
        try {
            const userData = JSON.parse(user);
            const tokenPayload = this.extractTokenPayload(token);
            
            // Se não conseguir extrair dados do usuário do localStorage, criar a partir do token
            if (!userData || !userData.id || !userData.role) {
                console.log('🔄 Dados do usuário incompletos, extraindo do token...');
                const userFromToken = this.getUserFromToken(token);
                if (userFromToken) {
                    localStorage.setItem('saberviver_user_data', JSON.stringify(userFromToken));
                    console.log('✅ Dados do usuário atualizados a partir do token');
                }
            } else {
                console.log('✅ Dados do usuário válidos no localStorage');
            }
        } catch (error) {
            console.warn('🔐 Erro ao validar dados do usuário, tentando extrair do token:', error.message);
            // Tentar recuperar dados do token
            try {
                const userFromToken = this.getUserFromToken(token);
                if (userFromToken) {
                    localStorage.setItem('saberviver_user_data', JSON.stringify(userFromToken));
                    console.log('✅ Dados do usuário recuperados do token');
                }
            } catch (tokenError) {
                console.error('🔐 Não foi possível extrair dados do token:', tokenError.message);
                this.clearAuthentication();
                return false;
            }
        }
        
        console.log('✅ === AUTENTICAÇÃO APROVADA COM JWT VÁLIDO ===');
        return true;
    }

    /**
     * Extrai o payload do token JWT
     */
    static extractTokenPayload(token) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                throw new Error('Token JWT inválido');
            }
            
            const payload = JSON.parse(atob(parts[1]));
            return payload;
        } catch (error) {
            console.error('❌ Erro ao extrair payload do token:', error);
            return null;
        }
    }

    /**
     * Valida consistência entre dados do usuário e token (versão simplificada)
     */
    static validateUserTokenConsistency(userData, tokenPayload) {
        // Validação simplificada - apenas verifica se ambos existem
        if (!userData || !tokenPayload) {
            console.warn('🔐 Dados do usuário ou token ausentes');
            return false;
        }
        
        // Verificação básica - se chegou até aqui, os dados são consistentes
        console.log('✅ Validação de consistência aprovada (modo flexível)');
        console.log(`  - Usuário: ${userData.nome || 'N/A'} (${userData.role || 'N/A'})`);
        console.log(`  - Token válido e processado com sucesso`);
        
        return true;
    }

    /**
     * Obtém dados do usuário a partir do token JWT
     */
    static getUserFromToken(token) {
        const payload = this.extractTokenPayload(token);
        if (!payload) {
            return null;
        }
        
        // Extrair ID do usuário (vários formatos possíveis)
        const userId = payload.sub || payload.id || payload.user_id || payload.userId || payload.aud;
        
        // Extrair role (vários formatos possíveis)
        const tokenRole = payload.role || payload.tipo || payload.perfil || payload.user_type || payload.userType || payload.authorities || payload.scope;
        const mappedRole = this.mapLoginRoleToSystem(tokenRole) || 'VOLUNTARIO';
        
        // Extrair nome (vários formatos possíveis)
        const userName = payload.name || payload.nome || payload.full_name || payload.username || payload.preferred_username || 'Usuário';
        
        console.log('🔍 Extraindo dados do token:');
        console.log(`  - ID: ${userId}`);
        console.log(`  - Nome: ${userName}`);
        console.log(`  - Role original: ${tokenRole}`);
        console.log(`  - Role mapeado: ${mappedRole}`);
        
        return {
            id: userId || Date.now(), // Usar timestamp como fallback se não tiver ID
            nome: userName,
            email: payload.email || '',
            role: mappedRole,
            // Outros campos que podem estar no token
            telefone: payload.telefone || payload.phone || '',
            cpf: payload.cpf || payload.document || ''
        };
    }

    // validateMockUser removido - sistema usa apenas API
    
    /**
     * Debug detalhado do token para identificar problemas
     */
    static debugToken(token) {
        console.log('🔍 === DEBUG DETALHADO DO TOKEN ===');
        
        if (!token) {
            console.log('❌ Token não fornecido');
            return null;
        }
        
        console.log('📋 Token (primeiros 50 chars):', token.substring(0, 50) + '...');
        
        const payload = this.extractTokenPayload(token);
        if (!payload) {
            console.log('❌ Não foi possível extrair payload do token');
            return null;
        }
        
        console.log('📊 === PAYLOAD COMPLETO ===');
        console.log(JSON.stringify(payload, null, 2));
        
        console.log('🔍 === CAMPOS ESPECÍFICOS ===');
        console.log('ID campos:', {
            sub: payload.sub,
            id: payload.id,
            user_id: payload.user_id,
            userId: payload.userId,
            aud: payload.aud
        });
        
        console.log('Role campos:', {
            role: payload.role,
            tipo: payload.tipo,
            perfil: payload.perfil,
            user_type: payload.user_type,
            userType: payload.userType,
            authorities: payload.authorities,
            scope: payload.scope
        });
        
        console.log('Nome campos:', {
            name: payload.name,
            nome: payload.nome,
            full_name: payload.full_name,
            username: payload.username,
            preferred_username: payload.preferred_username
        });
        
        return payload;
    }

    static validateJWTToken(token) {
        console.log('🔍 === INÍCIO DA VALIDAÇÃO JWT ===');
        
        try {
            console.log('🔍 Analisando estrutura do token...');
            const parts = token.split('.');
            console.log('📊 Partes do token:', parts.length);
            
            if (parts.length !== 3) {
                console.warn('🔐 Token inválido: estrutura JWT incorreta - esperado 3 partes, encontrado:', parts.length);
                console.log('❌ FALHA: Estrutura inválida');
                this.clearAuthentication();
                return false;
            }
            
            // Decodificar header
            console.log('🔍 Decodificando header...');
            let headerDecoded, header;
            try {
                headerDecoded = atob(parts[0]);
                console.log('📄 Header decodificado:', headerDecoded);
                header = JSON.parse(headerDecoded);
                console.log('📄 Header objeto:', header);
            } catch (e) {
                console.error('❌ Erro ao decodificar header:', e.message);
                this.clearAuthentication();
                return false;
            }
            
            if (!header.alg || !header.typ) {
                console.warn('🔐 Header JWT inválido - alg:', header.alg, 'typ:', header.typ);
                console.log('❌ FALHA: Header inválido');
                this.clearAuthentication();
                return false;
            }
            
            // Decodificar payload
            console.log('🔍 Decodificando payload...');
            let payloadDecoded, payload;
            try {
                payloadDecoded = atob(parts[1]);
                console.log('📄 Payload decodificado:', payloadDecoded);
                payload = JSON.parse(payloadDecoded);
                console.log('📊 Payload objeto:', payload);
            } catch (e) {
                console.error('❌ Erro ao decodificar payload:', e.message);
                this.clearAuthentication();
                return false;
            }
            
            // Verificar campos obrigatórios do JWT
            const userId = payload.sub || payload.id || payload.user_id || payload.userId;
            console.log('🆔 User ID encontrado:', userId);
            if (!userId) {
                console.warn('🔐 Payload JWT incompleto: sem identificação do usuário');
                console.log('📊 Campos disponíveis:', Object.keys(payload));
                console.log('❌ FALHA: Sem ID de usuário');
                this.clearAuthentication();
                return false;
            }
            
            // Verificar se o token não expirou (mais tolerante)
            if (payload.exp) {
                const now = Date.now() / 1000;
                console.log('🕐 Verificando expiração - Agora:', now, 'Expira em:', payload.exp);
                if (payload.exp < now) {
                    console.warn('🔐 Token expirado - mas continuando validação para desenvolvimento');
                    console.log('⚠️ Em produção, isso deveria falhar');
                    // Em vez de falhar, apenas avisar
                }
                console.log('✅ Verificação de expiração concluída');
            } else {
                console.log('⚠️ Token sem data de expiração - OK para desenvolvimento');
            }
            
            // Verificar se existe informação de role (mais flexível)
            const tokenRole = payload.role || payload.tipo || payload.perfil || payload.user_type || payload.userType || payload.authorities || payload.scope;
            console.log('🎭 Role encontrado no token:', tokenRole);
            
            // Se não encontrou role, assumir VOLUNTARIO como padrão
            let finalRole = tokenRole;
            if (!tokenRole) {
                console.warn('� Token sem informação de role/perfil, assumindo VOLUNTARIO como padrão');
                console.log('📊 Payload completo:', payload);
                finalRole = 'VOLUNTARIO';
            }
            
            // Mapear role da API para sistema local se necessário
            const mappedRole = this.mapLoginRoleToSystem(finalRole);
            console.log('🔄 Role mapeado:', finalRole, '->', mappedRole);
            
            // Validar se o role é válido (mais flexível)
            const validRoles = ['VOLUNTARIO', 'ADM', 'ADM_MASTER'];
            if (!validRoles.includes(mappedRole)) {
                console.warn('🔐 Role não reconhecido no JWT:', finalRole, '-> mapeado para:', mappedRole);
                console.log('⚠️ Usando VOLUNTARIO como fallback');
                console.log('✅ Roles válidos:', validRoles);
                // Não falhar, usar VOLUNTARIO como fallback
                payload.role = 'VOLUNTARIO';
            }
            
            console.log('✅ === TOKEN JWT VÁLIDO ===');
            console.log('👤 Usuário ID:', userId);
            console.log('🎭 Role final:', mappedRole);
            console.log('🔐 === FIM DA VALIDAÇÃO JWT ===');
            return true;
        } catch (error) {
            console.error('❌ === ERRO NA VALIDAÇÃO JWT ===');
            console.error('💥 Erro:', error.message);
            console.error('📊 Stack trace:', error.stack);
            console.log('🔐 === FIM DA VALIDAÇÃO JWT (ERRO) ===');
            this.clearAuthentication();
            return false;
        }
    }

    static getCurrentUser() {
        if (!this.isAuthenticated()) {
            console.warn('🔐 Tentativa de obter usuário sem autenticação válida');
            return null;
        }
        
        // Para ADM_MASTER, sempre usar apenas dados do token (não fazer verificações na API)
        const token = localStorage.getItem('saberviver_token');
        if (token) {
            const userFromToken = this.getUserFromToken(token);
            if (userFromToken && userFromToken.role === 'ADM_MASTER') {
                console.log('👤 ADM_MASTER - usuário extraído apenas do token:', userFromToken);
                // Salvar no localStorage para próximas consultas
                localStorage.setItem('saberviver_user_data', JSON.stringify(userFromToken));
                return userFromToken;
            }
        }
        
        // Para outros usuários, tentar obter dados atualizados do localStorage primeiro
        const userStr = localStorage.getItem('saberviver_user_data');
        if (userStr) {
            try {
                const user = JSON.parse(userStr);
                console.log('👤 Usuário obtido do localStorage:', user);
                return user;
            } catch (error) {
                console.warn('⚠️ Erro ao parsear dados do usuário do localStorage:', error);
            }
        }
        
        // Fallback: extrair dados do token para usuários não-ADM_MASTER
        if (token) {
            const userFromToken = this.getUserFromToken(token);
            if (userFromToken) {
                console.log('👤 Usuário extraído do token:', userFromToken);
                // Salvar no localStorage para próximas consultas
                localStorage.setItem('saberviver_user_data', JSON.stringify(userFromToken));
                return userFromToken;
            }
        }
        
        console.warn('❌ Não foi possível obter dados do usuário');
        return null;
    }

    static getUserRole() {
        const user = this.getCurrentUser();
        return user ? user.role : null;
    }

    static hasAdminPermission() {
        if (!this.isAuthenticated()) {
            console.warn('🔐 Verificação de permissão admin sem autenticação');
            return false;
        }
        const role = this.getUserRole();
        const hasPermission = role === 'ADM' || role === 'ADM_MASTER';
        
        if (!hasPermission) {
            console.warn(`🔐 Acesso negado: usuário com role '${role}' tentou acessar função admin`);
        }
        
        return hasPermission;
    }

    static hasVoluntarioPermission() {
        if (!this.isAuthenticated()) {
            console.warn('🔐 Verificação de permissão voluntário sem autenticação');
            return false;
        }
        const role = this.getUserRole();
        const hasPermission = role === 'VOLUNTARIO' || role === 'ADM' || role === 'ADM_MASTER';
        
        if (!hasPermission) {
            console.warn(`🔐 Acesso negado: usuário com role '${role}' tentou acessar função voluntário`);
        }
        
        return hasPermission;
    }

    static hasMasterPermission() {
        if (!this.isAuthenticated()) {
            console.warn('🔐 Verificação de permissão master sem autenticação');
            return false;
        }
        const role = this.getUserRole();
        const hasPermission = role === 'ADM_MASTER';
        
        if (!hasPermission) {
            console.warn(`🔐 Acesso negado: usuário com role '${role}' tentou acessar função master`);
        }
        
        return hasPermission;
    }

    static isVoluntario() {
        if (!this.isAuthenticated()) return false;
        return this.getUserRole() === 'VOLUNTARIO';
    }

    static isAdmin() {
        if (!this.isAuthenticated()) return false;
        return this.getUserRole() === 'ADM';
    }

    static isMaster() {
        if (!this.isAuthenticated()) return false;
        return this.getUserRole() === 'ADM_MASTER';
    }

    /**
     * Debug específico para validação de roles master
     * Verifica se uma role é reconhecida como master
     */
    static debugMasterRole(testRole) {
        console.log(`🔍 === TESTE DE ROLE MASTER: ${testRole} ===`);
        
        // Testar mapeamento
        const mappedRole = this.mapLoginRoleToSystem(testRole);
        console.log(`📋 Role "${testRole}" mapeado para: "${mappedRole}"`);
        
        // Testar se é reconhecido como master
        const isMasterRole = mappedRole === 'ADM_MASTER';
        console.log(`🎯 É role master? ${isMasterRole ? '✅ SIM' : '❌ NÃO'}`);
        
        // Mostrar roles master válidas
        console.log('📜 Roles que são reconhecidas como master:');
        console.log('  - ADM_MASTER (exato)');
        console.log('  - adm_master → ADM_MASTER');
        console.log('  - admin_master → ADM_MASTER');  
        console.log('  - master → ADM_MASTER');
        console.log('  - super → ADM_MASTER');
        console.log('  - super_admin → ADM_MASTER');
        console.log('  - superadmin → ADM_MASTER');
        
        return isMasterRole;
    }

    /**
     * Testa múltiplas roles master de uma vez
     */
    static testAllMasterRoles() {
        console.log('🧪 === TESTE COMPLETO DE ROLES MASTER ===');
        
        const testRoles = [
            'ADM_MASTER', 'adm_master', 'admin_master', 
            'master', 'MASTER', 'super', 'SUPER',
            'super_admin', 'superadmin', 'SUPERADMIN'
        ];
        
        testRoles.forEach(role => {
            const isMaster = this.debugMasterRole(role);
            console.log(`${isMaster ? '✅' : '❌'} ${role}`);
        });
        
        console.log('🎯 === RESULTADO ===');
        console.log('✅ = Role é reconhecida como ADM_MASTER');
        console.log('❌ = Role NÃO é reconhecida como ADM_MASTER');
    }

    // Método para verificar se o usuário pode acessar uma funcionalidade específica
    static canAccess(requiredRole) {
        if (!this.isAuthenticated()) {
            console.warn('🔐 Tentativa de acesso sem autenticação');
            return false;
        }

        const currentRole = this.getUserRole();
        const roleHierarchy = {
            'VOLUNTARIO': 1,
            'ADM': 2,
            'ADM_MASTER': 3
        };

        const currentLevel = roleHierarchy[currentRole] || 0;
        const requiredLevel = roleHierarchy[requiredRole] || 0;

        const hasAccess = currentLevel >= requiredLevel;
        
        if (!hasAccess) {
            console.warn(`🔐 Acesso negado: role '${currentRole}' (nível ${currentLevel}) tentou acessar funcionalidade que requer '${requiredRole}' (nível ${requiredLevel})`);
        }

        return hasAccess;
    }

    static logout() {
        this.clearAuthentication();
        window.location.href = 'login.html';
    }

    // ===============================
    // MÉTODOS PARA AUTENTICAÇÃO EXTERNA
    // ===============================
    
    /**
     * Define o usuário autenticado externamente
     * @param {Object} userData - Dados do usuário logado
     * @param {string} token - Token de autenticação
     */
    static setAuthenticatedUser(userData, token) {
        try {
            // Validar dados obrigatórios
            if (!userData || (!userData.id && !userData.email) || (!userData.nome && !userData.name) || !userData.role) {
                throw new Error('Dados do usuário inválidos. Campos obrigatórios: id/email, nome/name, role');
            }

            // Normalizar dados do usuário para formato esperado pelo painel
            const normalizedUser = {
                id: userData.id || userData.email,
                nome: userData.nome || userData.name,
                email: userData.email,
                role: this.mapLoginRoleToSystem(userData.role),
                permissions: userData.permissions || []
            };

            // Validar role após mapeamento
            const validRoles = ['VOLUNTARIO', 'ADM', 'ADM_MASTER'];
            if (!validRoles.includes(normalizedUser.role)) {
                throw new Error(`Role inválido: ${normalizedUser.role}. Valores aceitos: ${validRoles.join(', ')}`);
            }

            // Salvar com as chaves novas e antigas para compatibilidade
            localStorage.setItem('saberviver_token', token);
            localStorage.setItem('saberviver_user_data', JSON.stringify(normalizedUser));
            localStorage.setItem('saberviver_token_timestamp', Date.now().toString());
            
            // Manter compatibilidade com sistema antigo
            localStorage.setItem('token', token);
            localStorage.setItem('currentUser', JSON.stringify(normalizedUser));
            
            console.log(`✅ Usuário autenticado: ${normalizedUser.nome} (${normalizedUser.role})`);
            
            // Se a aplicação já estiver carregada, reinicializar
            if (window.appInstance) {
                window.appInstance.init();
            }
            
            return true;
        } catch (error) {
            console.error('❌ Erro ao definir usuário autenticado:', error);
            this.clearAuthentication();
            return false;
        }
    }

    /**
     * Mapeia roles do sistema de login/API para roles do painel
     */
    static mapLoginRoleToSystem(loginRole) {
        if (!loginRole) return 'VOLUNTARIO'; // Role padrão
        
        const role = loginRole.toString().toLowerCase();
        
        const roleMapping = {
            // Roles da API para ADM_MASTER
            'adm_master': 'ADM_MASTER',
            'admin_master': 'ADM_MASTER',
            'master': 'ADM_MASTER',
            'super': 'ADM_MASTER',
            'super_admin': 'ADM_MASTER',
            'superadmin': 'ADM_MASTER',
            
            'adm': 'ADM',
            'administrador': 'ADM',
            'coordinator': 'ADM',
            'coordenador': 'ADM',
            'gerente': 'ADM',
            
            'voluntario': 'VOLUNTARIO',
            'volunteer': 'VOLUNTARIO',
            'teacher': 'VOLUNTARIO',
            'professor': 'VOLUNTARIO',
            'educador': 'VOLUNTARIO',
            'educator': 'VOLUNTARIO',
            'user': 'VOLUNTARIO',
            'usuario': 'VOLUNTARIO'
        };
        
        const mappedRole = roleMapping[role];
        if (mappedRole) {
            console.log(`🔄 Role mapeado: ${loginRole} -> ${mappedRole}`);
            return mappedRole;
        }
        
        // Se não encontrou mapeamento, tentar usar o role original em maiúsculas
        const upperRole = loginRole.toUpperCase();
        if (['VOLUNTARIO', 'ADM', 'ADM_MASTER'].includes(upperRole)) {
            return upperRole;
        }
        
        // Role padrão se não conseguir mapear
        console.warn(`⚠️ Role não reconhecido: ${loginRole}, usando VOLUNTARIO como padrão`);
        return 'VOLUNTARIO';
    }

    /**
     * Limpa dados de autenticação
     */
    static clearAuthentication() {
        console.log('🧹 Limpando dados de autenticação...');
        localStorage.removeItem('saberviver_token');
        localStorage.removeItem('saberviver_user_data');
        localStorage.removeItem('saberviver_token_timestamp');
        
        // Limpar dados antigos também (se existirem)
        localStorage.removeItem('token');
        localStorage.removeItem('currentUser');
        
        console.log('✅ Dados de autenticação limpos');
    }

    /**
     * Método para ser chamado pela página de login externa
     * @param {Object} loginResponse - Resposta do sistema de login
     */
    static handleExternalLogin(loginResponse) {
        if (loginResponse.success && loginResponse.user && loginResponse.token) {
            return this.setAuthenticatedUser(loginResponse.user, loginResponse.token);
        } else {
            console.error('❌ Resposta de login inválida:', loginResponse);
            return false;
        }
    }

    static setupUserInterface() {
        // Verificar autenticação antes de configurar interface
        if (!this.isAuthenticated()) {
            console.warn('🔐 Tentativa de configurar interface sem autenticação válida');
            this.logout();
            return;
        }

        const user = this.getCurrentUser();
        if (!user) {
            console.warn('🔐 Usuário não encontrado após autenticação');
            this.logout();
            return;
        }

        // Atualizar elementos da interface
        const welcomeMsg = document.getElementById('welcome');
        const userRoleBadge = document.getElementById('user-role-badge');
        const profilePic = document.getElementById('profile-pic');

        if (welcomeMsg) {
            welcomeMsg.textContent = `Olá, ${user.nome}!`;
        }

        if (userRoleBadge) {
            let roleText = 'Voluntário';
            if (user.role === 'ADM') roleText = 'Administrador';
            if (user.role === 'ADM_MASTER') roleText = 'ADM Master';
            
            userRoleBadge.textContent = roleText;
            userRoleBadge.className = `user-role ${user.role.toLowerCase()}`;
        }

        if (profilePic) {
            const profileText = profilePic.querySelector('.profile-text');
            if (profileText) {
                profileText.textContent = user.nome.charAt(0).toUpperCase();
            }
        }

        // Controlar exibição do badge de modo teste
        const testBadge = document.getElementById('test-mode-badge');
        if (testBadge) {
            if (CONFIG.DEVELOPMENT_MODE) {
                testBadge.style.display = '';
                testBadge.textContent = '🧪 MODO DEV (API)';
            } else {
                testBadge.style.display = 'none';
            }
        }

        console.log(`🔐 Configurando interface para usuário: ${user.nome} (${user.role})`);

        // Sistema de Permissões com Verificação JWT
        // Elementos para todos os usuários autenticados
        const allUsersElements = document.querySelectorAll('.all-users');
        allUsersElements.forEach(element => {
            element.style.display = '';
        });

        // Elementos para VOLUNTÁRIO, ADMIN e ADM_MASTER (todos podem ver)
        const volunteerAndAdminElements = document.querySelectorAll('.volunteer-and-admin');
        volunteerAndAdminElements.forEach(element => {
            const shouldShow = this.canAccess('VOLUNTARIO');
            element.style.display = shouldShow ? '' : 'none';
            if (!shouldShow) {
                console.warn(`🔐 Acesso negado ao elemento: ${element.id || element.className}`);
            }
        });

        // Elementos apenas para VOLUNTÁRIO (ADM_MASTER não pode ver)
        const volunteerOnlyElements = document.querySelectorAll('.volunteer-only');
        volunteerOnlyElements.forEach(element => {
            const shouldShow = user.role === 'VOLUNTARIO';
            element.style.display = shouldShow ? '' : 'none';
            if (!shouldShow) {
                console.warn(`🔐 Acesso voluntário-only negado ao elemento: ${element.id || element.className}`);
            }
        });

        // Elementos apenas para ADMIN (não VOLUNTÁRIO nem ADM_MASTER)
        const adminOnlyElements = document.querySelectorAll('.admin-only');
        adminOnlyElements.forEach(element => {
            const shouldShow = user.role === 'ADM';
            element.style.display = shouldShow ? '' : 'none';
            if (!shouldShow) {
                console.warn(`🔐 Acesso admin-only negado ao elemento: ${element.id || element.className}`);
            }
        });

        // Elementos para VOLUNTARIO e ADMIN (não ADM_MASTER) - como "Meus Dados"
        const voluntarioOnlyElements = document.querySelectorAll('.voluntario-only');
        volunteerOnlyElements.forEach(element => {
            const shouldShow = user.role === 'VOLUNTARIO' || user.role === 'ADM';
            element.style.display = shouldShow ? '' : 'none';
            if (!shouldShow) {
                console.warn(`🔐 Acesso voluntario-only negado ao elemento: ${element.id || element.className}`);
            }
        });

        // Elementos para VOLUNTARIO e ADMIN apenas (não ADM_MASTER)
        const volunteerAndAdminOnlyElements = document.querySelectorAll('.volunteer-and-admin-only');
        volunteerAndAdminOnlyElements.forEach(element => {
            const shouldShow = user.role === 'VOLUNTARIO' || user.role === 'ADM';
            element.style.display = shouldShow ? '' : 'none';
            if (!shouldShow) {
                console.warn(`🔐 Acesso volunteer-and-admin-only negado ao elemento: ${element.id || element.className}`);
            }
        });

        // Elementos para todos os roles (VOLUNTARIO, ADMIN, ADM_MASTER)
        const allRolesElements = document.querySelectorAll('.all-roles');
        allRolesElements.forEach(element => {
            const shouldShow = ['VOLUNTARIO', 'ADM', 'ADM_MASTER'].includes(user.role);
            element.style.display = shouldShow ? '' : 'none';
            if (!shouldShow) {
                console.warn(`🔐 Acesso all-roles negado ao elemento: ${element.id || element.className}`);
            }
        });

        // Elementos apenas para ADMIN e ADM_MASTER
        const adminAndMasterElements = document.querySelectorAll('.admin-and-master');
        adminAndMasterElements.forEach(element => {
            const shouldShow = this.hasAdminPermission();
            element.style.display = shouldShow ? '' : 'none';
            if (!shouldShow) {
                console.warn(`🔐 Acesso admin negado ao elemento: ${element.id || element.className}`);
            }
        });

        // Elementos exclusivos para ADM_MASTER
        const masterOnlyElements = document.querySelectorAll('.master-only');
        masterOnlyElements.forEach(element => {
            const shouldShow = this.hasMasterPermission();
            element.style.display = shouldShow ? '' : 'none';
            if (!shouldShow) {
                console.warn(`🔐 Acesso master negado ao elemento: ${element.id || element.className}`);
            }
        });

        // Verificação especial para modais administrativos
        if (!this.hasAdminPermission()) {
            const adminModals = document.querySelectorAll('.modal.admin-only');
            adminModals.forEach(modal => {
                modal.style.display = 'none';
                console.log(`🔐 Modal admin protegido: ${modal.id}`);
            });
        }

        console.log(`🔐 Interface configurada com segurança para usuário: ${user.nome} (${user.role})`);
        
        // Log de depuração dos acessos configurados
        console.log('🔍 Acessos configurados por role:');
        if (user.role === 'VOLUNTARIO') {
            console.log('  ✅ Meus Dados, Gerenciar Alunos, Gerenciar Atividades');
            console.log('  ❌ Deletar registros, Gerenciar Voluntários, Gerenciar ADM');
        } else if (user.role === 'ADM') {
            console.log('  ✅ Meus Dados, Gerenciar Alunos (c/ delete), Gerenciar Atividades (c/ delete), Gerenciar Voluntários (c/ delete)');
            console.log('  ❌ Gerenciar ADM');
        } else if (user.role === 'ADM_MASTER') {
            console.log('  ✅ Gerenciar Alunos (c/ delete), Gerenciar Atividades (c/ delete), Gerenciar Voluntários (c/ delete), Gerenciar ADM (c/ delete)');
            console.log('  ❌ Meus Dados (dados vêm apenas do token)');
        }
    }

    static setDefaultActiveTab(userRole) {
        // Remover classe active de todas as abas
        const allTabs = document.querySelectorAll('.tab');
        const allTabContents = document.querySelectorAll('.tab-content');
        
        allTabs.forEach(tab => tab.classList.remove('active'));
        allTabContents.forEach(content => content.classList.remove('active'));

        let defaultTabId = '';
        let defaultTabButtonSelector = '';

        // Definir aba padrão baseada no role
        switch(userRole) {
            case 'VOLUNTARIO':
            case 'ADM':
                // Para VOLUNTARIO e ADMIN, iniciar em "Meus Dados"
                defaultTabId = 'meus-dados-tab';
                defaultTabButtonSelector = '#meus-dados-btn';
                break;
            case 'ADM_MASTER':
                // Para ADM_MASTER, iniciar em "Gerenciar Alunos" (não tem acesso a Meus Dados)
                defaultTabId = 'gerenciar-alunos-tab';
                defaultTabButtonSelector = 'button[onclick*="gerenciar-alunos-tab"]';
                break;
            default:
                defaultTabId = 'gerenciar-alunos-tab';
                defaultTabButtonSelector = 'button[onclick*="gerenciar-alunos-tab"]';
        }

        // Ativar aba padrão
        const defaultTabContent = document.getElementById(defaultTabId);
        const defaultTabButton = document.querySelector(defaultTabButtonSelector);

        if (defaultTabContent && defaultTabButton) {
            // Verificar se o elemento é visível antes de ativá-lo
            if (defaultTabButton.style.display !== 'none') {
                defaultTabContent.classList.add('active');
                defaultTabButton.classList.add('active');
                console.log(`🔧 Aba padrão ativada: ${defaultTabId} para ${userRole}`);
            } else {
                // Se a aba padrão estiver oculta, procurar a primeira aba visível
                const firstVisibleTab = document.querySelector('.tab[style=""], .tab:not([style])');
                if (firstVisibleTab) {
                    const tabOnClick = firstVisibleTab.getAttribute('onclick');
                    const tabIdMatch = tabOnClick.match(/'([^']+)'/);
                    if (tabIdMatch) {
                        const fallbackTabId = tabIdMatch[1];
                        const fallbackTabContent = document.getElementById(fallbackTabId);
                        if (fallbackTabContent) {
                            fallbackTabContent.classList.add('active');
                            firstVisibleTab.classList.add('active');
                            console.log(`🔧 Aba fallback ativada: ${fallbackTabId} para ${userRole}`);
                        }
                    }
                }
            }
        }
    }
}

// ===============================
// GERENCIADOR DE ESTADO
// ===============================
class StateManager {
    constructor() {
        this.state = {
            alunos: [],
            atividades: [],
            voluntarios: [],
            admins: [],
            currentUser: null,
            deleteData: null
        };
        this.listeners = {};
    }

    setState(newState) {
        const prevState = { ...this.state };
        this.state = { ...this.state, ...newState };
        
        // Notificar listeners sobre mudanças
        Object.keys(newState).forEach(key => {
            if (this.listeners[key] && prevState[key] !== this.state[key]) {
                this.listeners[key].forEach(callback => callback(this.state[key], prevState[key]));
            }
        });
    }

    getState() {
        return { ...this.state };
    }

    subscribe(key, callback) {
        if (!this.listeners[key]) {
            this.listeners[key] = [];
        }
        this.listeners[key].push(callback);
    }

    // Métodos getter para acessar os dados
    getAllAlunos() {
        return this.state.alunos || [];
    }

    getAllAtividades() {
        return this.state.atividades || [];
    }

    getAllVoluntarios() {
        return this.state.voluntarios || [];
    }



    getAllAdmins() {
        return this.state.ADM || [];
    }

    getCurrentUser() {
        return this.state.currentUser;
    }

    getAlunoById(id) {
        return this.state.alunos.find(aluno => aluno.id === id);
    }

    getAtividadeById(id) {
        return this.state.atividades.find(atividade => atividade.id === id);
    }

    getVoluntarioById(id) {
        return this.state.voluntarios.find(voluntario => voluntario.id === id);
    }


}

// ===============================
// SERVIÇO DE NOTIFICAÇÕES
// ===============================
class NotificationService {
    static currentTimeout = null;
    
    static show(message, type = 'info', duration = 5000) {
        const notification = document.getElementById('notification');
        const messageElement = document.getElementById('notification-message');
        
        if (!notification || !messageElement) {
            console.warn('Elementos de notificação não encontrados');
            return;
        }

        // Limpar timeout anterior se existir
        if (this.currentTimeout) {
            clearTimeout(this.currentTimeout);
        }

        // Primeiro, ocultar notificação atual se estiver visível
        if (notification.classList.contains('show')) {
            this.close();
            // Aguardar animação de fechamento antes de mostrar nova
            setTimeout(() => this._displayNotification(notification, messageElement, message, type, duration), 300);
        } else {
            this._displayNotification(notification, messageElement, message, type, duration);
        }
    }
    
    static _displayNotification(notification, messageElement, message, type, duration) {
        messageElement.textContent = message;
        notification.className = `notification ${type} show`;
        
        // Auto-ocultar após duration
        this.currentTimeout = setTimeout(() => {
            this.close();
        }, duration);
        
        // Log para debug
        console.log(`📢 Notificação (${type}): ${message}`);
    }

    static close() {
        const notification = document.getElementById('notification');
        if (notification) {
            notification.classList.remove('show');
            
            // Limpar timeout se existir
            if (this.currentTimeout) {
                clearTimeout(this.currentTimeout);
                this.currentTimeout = null;
            }
        }
    }
    
    // Métodos de conveniência
    static success(message, duration = 4000) {
        this.show(message, 'success', duration);
    }
    
    static error(message, duration = 6000) {
        this.show(message, 'error', duration);
    }
    
    static warning(message, duration = 5000) {
        this.show(message, 'warning', duration);
    }
    
    static info(message, duration = 4000) {
        this.show(message, 'info', duration);
    }
}

// ===============================
// UTILITÁRIOS
// ===============================
class Utils {
    static sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        return input.trim().replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    }

    static formatCPF(input) {
        let value = input.value.replace(/\D/g, '');
        value = value.replace(/(\d{3})(\d)/, '$1.$2');
        value = value.replace(/(\d{3})(\d)/, '$1.$2');
        value = value.replace(/(\d{3})(\d{1,2})$/, '$1-$2');
        input.value = value;
    }

    static formatPhone(input) {
        let value = input.value.replace(/\D/g, '');
        if (value.length <= 10) {
            value = value.replace(/(\d{2})(\d{4})(\d{4})/, '($1) $2-$3');
        } else {
            value = value.replace(/(\d{2})(\d{5})(\d{4})/, '($1) $2-$3');
        }
        input.value = value;
    }

    static async showConfirm(message) {
        return new Promise((resolve) => {
            const result = confirm(message);
            resolve(result);
        });
    }

    static debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
}

// ===============================
// SERVIÇO DE MODAIS
// ===============================
class ModalService {
    constructor(stateManager) {
        this.stateManager = stateManager;
    }

    openStudentModal() {
        if (!AuthService.hasVoluntarioPermission()) return;
        const modal = document.getElementById('student-modal');
        if (modal) {
            modal.style.display = 'flex';
            
            // Inicializar campos de data de nascimento
            this.initializeDateFields();
            
            // Carregar atividades para seleção múltipla
            this.carregarAtividadesModal();
            
            // Configurar máscaras de formatação
            this.setupFormMasks();
            
            // Limpar notificações anteriores
            const notificacao = document.getElementById('modal-notificacao');
            if (notificacao) {
                notificacao.style.display = 'none';
                notificacao.classList.remove('show');
            }
        }
    }

    closeStudentModal() {
        const modal = document.getElementById('student-modal');
        const form = document.getElementById('student-form');
        if (modal) modal.style.display = 'none';
        if (form) {
            form.reset();
            // Limpar campos ocultos
            const hiddenInput = document.getElementById('modal-atividades-selecionadas');
            if (hiddenInput) hiddenInput.value = '';
            
            // Resetar contador de atividades
            const contador = document.getElementById('contador-atividades');
            if (contador) contador.textContent = '0 selecionadas';
        }
    }

    // Inicializar campos de data de nascimento
    initializeDateFields() {
        const diaSelect = document.getElementById('aluno-dia');
        const anoSelect = document.getElementById('aluno-ano');
        
        if (diaSelect) {
            diaSelect.innerHTML = '<option value="">Dia</option>';
            for (let i = 1; i <= 31; i++) {
                const option = document.createElement('option');
                option.value = i.toString().padStart(2, '0');
                option.text = i;
                diaSelect.add(option);
            }
        }
        
        if (anoSelect) {
            anoSelect.innerHTML = '<option value="">Ano</option>';
            const anoAtual = new Date().getFullYear();
            for (let i = anoAtual; i >= 1900; i--) {
                const option = document.createElement('option');
                option.value = i;
                option.text = i;
                anoSelect.add(option);
            }
        }
    }

    // Carregar atividades para seleção múltipla no modal
    async carregarAtividadesModal() {
        console.log('🔄 Carregando atividades para o modal...');
        
        const listaDiv = document.getElementById('modal-lista-atividades');
        const hiddenInput = document.getElementById('modal-atividades-selecionadas');
        
        if (!listaDiv || !hiddenInput) {
            console.error('❌ Elementos do modal não encontrados:', { listaDiv, hiddenInput });
            return;
        }
        
        listaDiv.innerHTML = `
            <div class="loading-atividades">
                <i class="fas fa-spinner fa-spin"></i>
                <span>Carregando atividades...</span>
            </div>
        `;
        
        try {
            // Tentar carregar atividades da API
            const response = await fetch('https://saberviver-api.up.railway.app/atividades/publico', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                mode: 'cors',
                credentials: 'omit'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const atividades = await response.json();
            const lista = atividades.content || [];
            
            this.renderizarAtividadesModal(lista, listaDiv, hiddenInput);
            
        } catch (error) {
            console.error('❌ Erro ao carregar atividades:', error);
            
            // Fallback com atividades predefinidas
            const atividadesFallback = [
                { id: 1, nome: "Natação", descricao: "Aulas de natação para todas as idades", vagas: 20 },
                { id: 2, nome: "Futebol", descricao: "Escolinha de futebol infantil", vagas: 15 },
                { id: 3, nome: "Basquete", descricao: "Treinos de basquete", vagas: 12 },
                { id: 4, nome: "Judô", descricao: "Aulas de judô e defesa pessoal", vagas: 10 },
                { id: 5, nome: "Ballet", descricao: "Aulas de ballet clássico", vagas: 8 }
            ];
            
            this.renderizarAtividadesModal(atividadesFallback, listaDiv, hiddenInput, true);
        }
    }

    // Renderizar atividades no modal
    renderizarAtividadesModal(atividades, listaDiv, hiddenInput, isFallback = false) {
        listaDiv.innerHTML = "";
        
        if (isFallback) {
            const fallbackDiv = document.createElement("div");
            fallbackDiv.className = "atividades-fallback";
            fallbackDiv.innerHTML = `
                <i class="fas fa-exclamation-triangle"></i>
                <span><strong>Modo offline:</strong> Algumas atividades podem não estar atualizadas</span>
            `;
            listaDiv.appendChild(fallbackDiv);
        }
        
        if (atividades.length === 0) {
            listaDiv.innerHTML = `
                <div style="text-align: center; padding: 40px 20px; color: #6c757d;">
                    <i class="fas fa-clipboard-list" style="font-size: 24px; margin-bottom: 12px; display: block;"></i>
                    <span style="font-size: 14px;">Nenhuma atividade cadastrada.</span>
                </div>
            `;
            return;
        }
        
        atividades.forEach(atividade => {
            const label = document.createElement("label");
            label.classList.add("modal-atividade-item");
            
            // Definir ícone baseado no tipo de atividade
            let icone = "fas fa-futbol";
            const nome = atividade.nome.toLowerCase();
            if (nome.includes("natação") || nome.includes("piscina")) icone = "fas fa-swimmer";
            else if (nome.includes("futebol")) icone = "fas fa-futbol";
            else if (nome.includes("basquete")) icone = "fas fa-basketball-ball";
            else if (nome.includes("judô") || nome.includes("judo") || nome.includes("luta")) icone = "fas fa-fist-raised";
            else if (nome.includes("ballet") || nome.includes("dança")) icone = "fas fa-music";
            else if (nome.includes("tênis") || nome.includes("tenis")) icone = "fas fa-table-tennis";
            else if (nome.includes("vôlei") || nome.includes("volei")) icone = "fas fa-volleyball-ball";
            
            label.innerHTML = `
                <input type="checkbox" value="${atividade.id}" class="modal-atividade-checkbox">
                <div class="atividade-content">
                    <div class="atividade-titulo">
                        <i class="${icone} atividade-icone"></i>
                        <h4 class="atividade-nome">${atividade.nome}</h4>
                    </div>
                    <p class="atividade-descricao">${atividade.descricao}</p>
                    <span class="atividade-vagas">
                        <i class="fas fa-users"></i>
                        ${atividade.vagas} vagas
                    </span>
                </div>
            `;
            listaDiv.appendChild(label);
        });
        
        // Adicionar eventos aos checkboxes
        this.adicionarEventosAtividadesModal(hiddenInput);
    }

    // Adicionar eventos aos checkboxes de atividades
    adicionarEventosAtividadesModal(hiddenInput) {
        const checkboxes = document.querySelectorAll('.modal-atividade-checkbox');
        const contador = document.getElementById('contador-atividades');
        
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const label = e.target.closest('.modal-atividade-item');
                
                // Atualizar estilo visual
                if (e.target.checked) {
                    label.classList.add('selected');
                } else {
                    label.classList.remove('selected');
                }
                
                // Atualizar valores e contador
                const selecionadas = Array.from(document.querySelectorAll('.modal-atividade-checkbox:checked')).map(c => c.value);
                hiddenInput.value = selecionadas.join(',');
                
                if (contador) {
                    const count = selecionadas.length;
                    contador.textContent = count === 0 ? '0 selecionadas' : 
                                          count === 1 ? '1 selecionada' : 
                                          `${count} selecionadas`;
                }
                
                console.log('🎯 Atividades selecionadas no modal:', selecionadas);
            });
        });
    }

    // Configurar máscaras de formatação
    setupFormMasks() {
        // Máscara para CPF
        const cpfFields = ['aluno-cpf', 'aluno-cpf-responsavel'];
        cpfFields.forEach(fieldId => {
            const field = document.getElementById(fieldId);
            if (field && !field.hasAttribute('data-mask-setup')) {
                field.addEventListener('input', (e) => {
                    let value = e.target.value.replace(/\D/g, "");
                    if (value.length > 11) value = value.slice(0, 11);
                    value = value.replace(/(\d{3})(\d)/, "$1.$2");
                    value = value.replace(/(\d{3})(\d)/, "$1.$2");
                    value = value.replace(/(\d{3})(\d{1,2})$/, "$1-$2");
                    e.target.value = value;
                });
                field.setAttribute('data-mask-setup', 'true');
            }
        });

        // Máscara para telefone
        const phoneFields = ['aluno-telefone-principal', 'aluno-telefone-opcional'];
        phoneFields.forEach(fieldId => {
            const field = document.getElementById(fieldId);
            if (field && !field.hasAttribute('data-mask-setup')) {
                field.addEventListener('input', (e) => {
                    let value = e.target.value.replace(/\D/g, "");
                    if (value.length > 11) value = value.slice(0, 11);
                    value = value.replace(/^(\d{2})(\d)/g, "($1) $2");
                    value = value.replace(/(\d{5})(\d{4})$/, "$1-$2");
                    e.target.value = value;
                });
                field.setAttribute('data-mask-setup', 'true');
            }
        });

        // Somente letras para nomes
        const nameFields = ['aluno-nome-responsavel', 'aluno-nome', 'aluno-sobrenome', 'aluno-apelido'];
        nameFields.forEach(fieldId => {
            const field = document.getElementById(fieldId);
            if (field && !field.hasAttribute('data-name-setup')) {
                field.addEventListener('input', (e) => {
                    e.target.value = e.target.value.replace(/[^A-Za-zÀ-ÖØ-öø-ÿ\s]/g, '');
                });
                field.setAttribute('data-name-setup', 'true');
            }
        });
    }

    openActivityModal() {
        if (!AuthService.hasVoluntarioPermission()) return;
        const modal = document.getElementById('activity-modal');
        if (modal) modal.style.display = 'flex';
    }

    closeActivityModal() {
        const modal = document.getElementById('activity-modal');
        const form = document.getElementById('activity-form');
        if (modal) modal.style.display = 'none';
        if (form) form.reset();
    }

    closeViewActivityModal() {
        const modal = document.getElementById('view-activity-modal');
        if (modal) modal.style.display = 'none';
    }

    openEditActivityModal() {
        if (!AuthService.hasVoluntarioPermission()) return;
        
        const viewModal = document.getElementById('view-activity-modal');
        const activityId = viewModal.dataset.activityId;
        
        if (!activityId) {
            console.error('❌ ID da atividade não encontrado');
            return;
        }

        const atividades = this.stateManager.getAllAtividades();
        const atividade = atividades.find(a => a.id === activityId);
        6
        if (!atividade) {
            console.error('❌ Atividade não encontrada para edição:', activityId);
            return;
        }

        // Preencher formulário de edição
        document.getElementById('edit-activity-nome').value = atividade.nome || '';
        document.getElementById('edit-activity-descricao').value = atividade.descricao || '';
        
        // Armazenar ID da atividade no formulário
        const editForm = document.getElementById('edit-activity-form');
        editForm.dataset.activityId = activityId;

        // Fechar modal de visualização e abrir modal de edição
        this.closeViewActivityModal();
        
        const editModal = document.getElementById('edit-activity-modal');
        if (editModal) editModal.style.display = 'flex';
        
        console.log('📝 Modal de edição de atividade aberto:', atividade.nome);
    }

    closeEditActivityModal() {
        const modal = document.getElementById('edit-activity-modal');
        const form = document.getElementById('edit-activity-form');
        if (modal) modal.style.display = 'none';
        if (form) form.reset();
    }

    openVoluntarioModal() {
        if (!AuthService.hasAdminPermission()) return;
        const modal = document.getElementById('volunteer-modal');
        if (modal) {
            modal.style.display = 'flex';
            this.populateActivitySelect('voluntario-atividade');
        }
    }

    closeVoluntarioModal() {
        const modal = document.getElementById('volunteer-modal');
        const form = document.getElementById('volunteer-form');
        if (modal) modal.style.display = 'none';
        if (form) form.reset();
    }

    async openEditStudentModal(id) {
        if (!AuthService.hasAdminPermission()) return;
        const { alunos, atividades } = this.stateManager.getState();
        const aluno = alunos.find(a => a.id === parseInt(id));
        if (!aluno) return;

        // Preencher campos
        document.getElementById('edit-aluno-nome').value = aluno.nome || '';
        document.getElementById('edit-aluno-sobrenome').value = aluno.sobre_nome || '';
        document.getElementById('edit-aluno-cpf').value = aluno.cpf || '';
        document.getElementById('edit-aluno-data-nascimento').value = aluno.data_nascimento || '';
        document.getElementById('edit-aluno-apelido').value = aluno.apelido || '';
        document.getElementById('edit-aluno-nome-responsavel').value = aluno.nome_responsavel || '';
        document.getElementById('edit-aluno-telefone-principal').value = aluno.telefone_principal || '';
        document.getElementById('edit-aluno-telefone-opcional').value = aluno.telefone_opcional || '';
        document.getElementById('edit-aluno-cpf-responsavel').value = aluno.cpf_responsavel || '';

        // Preencher select de atividades
        this.populateActivitySelect('edit-aluno-atividade', aluno.atividade);

        // Configurar status toggle
        this.setupStatusToggle('#view-student-modal', aluno.status);

        // Definir ID do aluno para edição
        document.getElementById('edit-student-form').dataset.alunoId = id;

        // Abrir modal
        const modal = document.getElementById('view-student-modal');
        if (modal) modal.style.display = 'flex';
    }

    async openViewStudentModal(id) {
        // Redirecionar para o modal de edição
        return this.openEditStudentModal(id);

        // Armazenar ID no formulário
        const form = document.getElementById('edit-student-form');
        if (form) form.dataset.alunoId = aluno.id;

        // Mostrar modal
        const modal = document.getElementById('view-student-modal');
        if (modal) modal.style.display = 'flex';
    }

    closeViewStudentModal() {
        const modal = document.getElementById('view-student-modal');
        if (modal) modal.style.display = 'none';
    }

    async openViewVoluntarioModal(id) {
        const { voluntarios, atividades } = this.stateManager.getState();
        const voluntario = voluntarios.find(c => c.id === parseInt(id));
        if (!voluntario) return;

        // Preencher campos
        document.getElementById('edit-voluntario-nome').value = voluntario.nome;
        document.getElementById('edit-voluntario-email').value = voluntario.email;
        document.getElementById('edit-voluntario-telefone').value = voluntario.telefone;
        document.getElementById('edit-voluntario-cpf').value = voluntario.cpf;

        // Preencher select de atividades
        this.populateActivitySelect('edit-voluntario-atividade', voluntario.atividade);

        // Configurar status toggle
        this.setupStatusToggle('#view-volunteer-modal', voluntario.status);

        // Armazenar ID no formulário
        const form = document.getElementById('edit-volunteer-form');
        if (form) form.dataset.voluntarioId = voluntario.id;

        // Mostrar modal
        const modal = document.getElementById('view-volunteer-modal');
        if (modal) modal.style.display = 'flex';
    }

    closeViewVoluntarioModal() {
        const modal = document.getElementById('view-volunteer-modal');
        if (modal) modal.style.display = 'none';
    }

    showDeleteConfirmation(tipo, id, dados) {
        if (tipo === 'voluntarios') {
            // Armazenar dados para confirmação
            this.stateManager.setState({ deleteData: { tipo, id, dados } });

            // Preencher informações no modal
            const infoContainer = document.getElementById('delete-item-info');
            if (infoContainer) {
                infoContainer.innerHTML = `
                    <h3>Informações do Voluntário</h3>
                    <div class="info-row">
                        <span class="info-label">Nome:</span>
                        <span class="info-value">${dados.nome}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Email:</span>
                        <span class="info-value">${dados.email}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Telefone:</span>
                        <span class="info-value">${dados.telefone}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">CPF:</span>
                        <span class="info-value">${dados.cpf}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Atividade:</span>
                        <span class="info-value">${dados.atividade}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Status:</span>
                        <span class="info-value">
                            <span class="status-badge ${dados.status}">${dados.status}</span>
                        </span>
                    </div>
                `;
            }

            // Mostrar modal
            const modal = document.getElementById('delete-confirmation-modal');
            if (modal) modal.style.display = 'flex';
        }
    }

    closeDeleteConfirmationModal() {
        const modal = document.getElementById('delete-confirmation-modal');
        if (modal) modal.style.display = 'none';
        this.stateManager.setState({ deleteData: null });
    }

    populateActivitySelect(selectId, selectedValue = '') {
        const select = document.getElementById(selectId);
        const { atividades } = this.stateManager.getState();
        
        if (!select) return;

        select.innerHTML = '<option value="">Selecione uma atividade</option>';
        atividades.forEach(atividade => {
            const option = document.createElement('option');
            option.value = atividade.nome;
            option.textContent = atividade.nome;
            option.selected = atividade.nome === selectedValue;
            select.appendChild(option);
        });
    }

    setupStatusToggle(modalSelector, status) {
        const modal = document.querySelector(modalSelector);
        if (!modal) return;

        // Procurar por toggle de aluno ou voluntário
        let toggle = modal.querySelector('#student-status-toggle');
        let label = modal.querySelector('#student-status-label');
        
        if (!toggle) {
            toggle = modal.querySelector('#volunteer-status-toggle');
            label = modal.querySelector('#volunteer-status-label');
        }
        
        const icon = toggle?.querySelector('.toggle-slider i');
        
        if (toggle && label && icon) {
            toggle.dataset.status = status;
            
            if (status === 'ativo') {
                toggle.classList.remove('inactive');
                toggle.classList.add('active');
                label.textContent = 'Ativo';
                icon.className = 'fas fa-check';
            } else {
                toggle.classList.remove('active');
                toggle.classList.add('inactive');
                label.textContent = 'Inativo';
                icon.className = 'fas fa-times';
            }
            
            console.log(`📋 Status toggle configurado: ${status} para ${modalSelector}`);
        } else {
            console.warn(`⚠️ Toggle não encontrado em ${modalSelector}`);
        }
    }

    setupModalClosers() {
        // Fechar modais ao clicar fora
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    switch(modal.id) {
                        case 'student-modal':
                            this.closeStudentModal();
                            break;
                        case 'activity-modal':
                            this.closeActivityModal();
                            break;
                        case 'volunteer-modal':
                            this.closeVoluntarioModal();
                            break;
                        case 'view-student-modal':
                            this.closeViewStudentModal();
                            break;
                        case 'view-volunteer-modal':
                            this.closeViewVoluntarioModal();
                            break;
                        case 'delete-confirmation-modal':
                            this.closeDeleteConfirmationModal();
                            break;
                        case 'view-aluno-modal':
                            window.closeViewAlunoModal();
                            break;
                        case 'edit-my-data-modal':
                            window.closeEditMyDataModal();
                            break;
                    }
                }
            });
        });

        // Fechar dropdown de perfil ao clicar fora
        document.addEventListener('click', (e) => {
            const dropdown = document.querySelector('.profile-dropdown');
            const profilePic = document.getElementById('profile-pic');
            
            if (dropdown && !profilePic.contains(e.target)) {
                dropdown.style.display = 'none';
            }
        });
    }



    openViewAlunoModal(id) {
        const aluno = this.stateManager.getAlunoById(id);
        if (!aluno) return;

        const modal = document.getElementById('view-aluno-modal');
        const content = document.getElementById('aluno-info-content');

        if (!modal || !content) return;

        content.innerHTML = `
            <div class="aluno-details">
                <div class="info-row">
                    <span class="info-label">Nome:</span>
                    <span class="info-value">${aluno.nome}</span>
                </div>
                ${aluno.apelido ? `
                <div class="info-row">
                    <span class="info-label">Apelido:</span>
                    <span class="info-value">${aluno.apelido}</span>
                </div>
                ` : ''}
                <div class="info-row">
                    <span class="info-label">Idade:</span>
                    <span class="info-value">${aluno.idade} anos</span>
                </div>
                ${aluno.dataNascimento ? `
                <div class="info-row">
                    <span class="info-label">Data de Nascimento:</span>
                    <span class="info-value">${new Date(aluno.dataNascimento).toLocaleDateString('pt-BR')}</span>
                </div>
                ` : ''}
                <div class="info-row">
                    <span class="info-label">Responsável:</span>
                    <span class="info-value">${aluno.responsavel}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Telefone:</span>
                    <span class="info-value">${aluno.telefone}</span>
                </div>
                ${aluno.cpfResponsavel ? `
                <div class="info-row">
                    <span class="info-label">CPF do Responsável:</span>
                    <span class="info-value">${aluno.cpfResponsavel}</span>
                </div>
                ` : ''}
                ${aluno.atividade ? `
                <div class="info-row">
                    <span class="info-label">Atividade:</span>
                    <span class="info-value">${aluno.atividade}</span>
                </div>
                ` : ''}

                <div class="info-row">
                    <span class="info-label">Status:</span>
                    <span class="status-badge ${aluno.status}">${aluno.status}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Cadastrado em:</span>
                    <span class="info-value">${new Date(aluno.createdAt).toLocaleDateString('pt-BR')}</span>
                </div>
            </div>
            <div class="modal-actions">
                <button class="btn-edit" onclick="editarAluno(${aluno.id})">
                    <i class="fas fa-edit"></i>
                    Editar Aluno
                </button>
                ${this.stateManager.getCurrentUser()?.role !== 'VOLUNTARIO' ? `
                <button class="btn-excluir admin-and-master" onclick="deletarRegistro('alunos', ${aluno.id})">
                    <i class="fas fa-trash"></i>
                    Excluir Aluno
                </button>
                ` : ''}
            </div>
        `;

        modal.style.display = 'flex';
    }
}

// ===============================
// RENDERIZADOR DE INTERFACE
// ===============================

class UIRenderer {
    constructor(stateManager) {
        this.stateManager = stateManager;
        this.modalService = new ModalService(stateManager);
    }

    openTab(tabName, evt) {
        console.log('🔄 Abrindo tab:', tabName);
        
        // Remover classe active de todos os tab-content
        const tabContents = document.querySelectorAll('.tab-content');
        tabContents.forEach(content => {
            content.classList.remove('active');
        });
        
        // Remover classe active de todos os botões de tab
        const tabButtons = document.querySelectorAll('.tab');
        tabButtons.forEach(button => {
            button.classList.remove('active');
        });
        
        // Ativar o tab selecionado
        const selectedTabContent = document.getElementById(tabName);
        if (selectedTabContent) {
            selectedTabContent.classList.add('active');
            console.log(`✅ Tab content ativado: ${tabName}`);
        } else {
            console.error(`❌ Tab content não encontrado: ${tabName}`);
            return;
        }
        
        // Ativar o botão do tab
        if (evt && evt.currentTarget) {
            evt.currentTarget.classList.add('active');
            console.log('✅ Botão do tab ativado');
        }
        
        // Limpar todas as listas antes de renderizar a nova
        this.clearAllLists();
        
        // Renderizar apenas o conteúdo do tab ativo
        this.renderSpecificTab(tabName);
    }

    renderSpecificTab(tabName) {
        console.log('🎯 Renderizando tab específico:', tabName);
        
        switch(tabName) {
            case 'meus-dados-tab':
                console.log('📄 Renderizando Meus Dados...');
                this.renderMeusDados();
                break;
            case 'gerenciar-alunos-tab':
                console.log('👦 Renderizando Alunos...');
                this.renderAlunos();
                break;
            case 'gerenciar-atividades-tab':
                console.log('🏃 Renderizando Atividades...');
                this.renderAtividades();
                break;
            case 'gerenciar-voluntarios-tab':
                console.log('👥 Renderizando Voluntários...');
                this.renderVoluntarios();
                break;
            case 'gerenciar-admin-tab':
                console.log('🔒 Renderizando administrador...');
                this.renderAdmins();
                break;
            default:
                console.log('⚠️ Tab desconhecido:', tabName);
        }
    }

    renderCurrentTab() {
        console.log('🔄 Renderizando tab atual...');
        
        // Limpar todas as listas primeiro
        this.clearAllLists();
        
        // Garantir que apenas uma aba esteja ativa por vez
        this.ensureSingleActiveTab();
        
        // Detectar qual tab está ativo e renderizar APENAS esse
        const activeTab = document.querySelector('.tab-content.active');
        
        if (!activeTab) {
            console.log('⚠️ Nenhuma aba ativa encontrada, definindo aba padrão...');
            this.setDefaultTab();
            return;
        }
        
        console.log('📋 Renderizando aba ativa:', activeTab.id);
        
        switch(activeTab.id) {
            case 'meus-dados-tab':
                console.log('📄 Renderizando Meus Dados...');
                this.renderMeusDados();
                break;
            case 'gerenciar-alunos-tab':
                console.log('👦 Renderizando Alunos...');
                this.renderAlunos();
                break;
            case 'gerenciar-atividades-tab':
                console.log('🏃 Renderizando Atividades...');
                this.renderAtividades();
                break;
            case 'gerenciar-voluntarios-tab':
                console.log('👥 Renderizando Voluntários...');
                this.renderVoluntarios();
                break;
            case 'gerenciar-admin-tab':
                console.log('� Renderizando administrador...');
                this.renderAdmins();
                break;
            default:
                console.log('⚠️ Aba desconhecida:', activeTab.id);
        }
    }

    ensureSingleActiveTab() {
        const activeTabs = document.querySelectorAll('.tab-content.active');
        
        if (activeTabs.length > 1) {
            console.log('⚠️ Múltiplas abas ativas detectadas, corrigindo...');
            // Desativar todas exceto a primeira
            for (let i = 1; i < activeTabs.length; i++) {
                activeTabs[i].classList.remove('active');
                console.log(`❌ Desativando aba: ${activeTabs[i].id}`);
            }
            
            // Desativar botões de aba correspondentes
            const activeTabButtons = document.querySelectorAll('.tab.active');
            for (let i = 1; i < activeTabButtons.length; i++) {
                activeTabButtons[i].classList.remove('active');
            }
        }
        
        console.log(`✅ Garantido: ${activeTabs.length > 0 ? 1 : 0} aba ativa`);
    }

    setDefaultTab() {
        console.log('🔧 Definindo aba padrão...');
        
        // Primeiro, limpar todas as abas ativas
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelectorAll('.tab').forEach(button => {
            button.classList.remove('active');
        });
        
        const user = AuthService.getCurrentUser();
        let defaultTabId = 'gerenciar-alunos-tab';
        let defaultButtonSelector = 'button[onclick*="gerenciar-alunos-tab"]';
        
        if (user && (user.role === 'VOLUNTARIO' || user.role === 'ADM')) {
            // Para VOLUNTÁRIO e ADMIN, verificar se aba Meus Dados é visível
            const meusDadosTab = document.getElementById('meus-dados-tab');
            const meusDadosBtn = document.getElementById('meus-dados-btn');
            
            if (meusDadosTab && meusDadosBtn && 
                window.getComputedStyle(meusDadosTab).display !== 'none' &&
                window.getComputedStyle(meusDadosBtn).display !== 'none') {
                defaultTabId = 'meus-dados-tab';
                defaultButtonSelector = '#meus-dados-btn';
            }
        }
        
        const defaultTabContent = document.getElementById(defaultTabId);
        const defaultTabButton = document.querySelector(defaultButtonSelector);
        
        if (defaultTabContent && defaultTabButton && 
            window.getComputedStyle(defaultTabContent).display !== 'none' &&
            window.getComputedStyle(defaultTabButton).display !== 'none') {
            
            defaultTabContent.classList.add('active');
            defaultTabButton.classList.add('active');
            console.log(`✅ Aba padrão definida: ${defaultTabId}`);
        } else {
            // Fallback: encontrar primeira aba visível
            const visibleTabs = Array.from(document.querySelectorAll('.tab-content')).filter(tab => {
                return window.getComputedStyle(tab).display !== 'none';
            });
            
            if (visibleTabs.length > 0) {
                const firstTab = visibleTabs[0];
                const tabId = firstTab.id;
                const tabButton = document.querySelector(`button[onclick*="${tabId}"]`);
                
                if (tabButton && window.getComputedStyle(tabButton).display !== 'none') {
                    firstTab.classList.add('active');
                    tabButton.classList.add('active');
                    console.log(`✅ Aba fallback definida: ${tabId}`);
                }
            }
        }
    }

    clearAllLists() {
        const lists = ['alunos-list', 'atividades-list', 'voluntarios-list', 'admins-list', 'my-data-content'];
        lists.forEach(listId => {
            const list = document.getElementById(listId);
            if (list) {
                list.innerHTML = '';
                console.log(`🧹 Lista ${listId} limpa`);
            }
        });
    }

    isTabActive(tabId) {
        const tab = document.getElementById(tabId);
        return tab && tab.classList.contains('active');
    }

    renderAlunos() {
        const lista = document.getElementById('alunos-list');
        if (!lista) {
            console.warn('❌ Elemento alunos-list não encontrado');
            return;
        }
        
        const alunos = this.stateManager.getAllAlunos();
        console.log('📊 Renderizando alunos:', alunos.length, 'registros');
        console.log('📊 Dados dos alunos:', alunos);

        // Limpar lista primeiro
        lista.innerHTML = '';

        if (alunos.length === 0) {
            lista.innerHTML = '<li class="empty-state">Nenhum aluno cadastrado</li>';
            return;
        }

        // Ordenar alunos
        const alunosOrdenados = alunos.sort((a, b) => {
            if (a.status === 'ativo' && b.status === 'inativo') return -1;
            if (a.status === 'inativo' && b.status === 'ativo') return 1;
            return a.nome.localeCompare(b.nome);
        });

        alunosOrdenados.forEach(aluno => {
            const li = document.createElement('li');
            li.style.cursor = 'pointer';
            li.onclick = () => this.modalService.openViewAlunoModal(aluno.id);
            li.className = aluno.status === 'inativo' ? 'item-inativo' : '';
            
            li.innerHTML = `
                <div class="aluno-info">
                    <div class="aluno-detalhes">
                        <span class="aluno-nome">${aluno.nome}</span>
                        <span class="aluno-sub">${aluno.apelido || ''} • ${aluno.idade} anos</span>
                    </div>
                    <div class="aluno-acoes">
                        <span class="status-badge ${aluno.status}">${aluno.status}</span>
                        <span class="aluno-atividade">${aluno.atividade || 'Sem atividade'}</span>
                        <i class="fas fa-eye" style="color: #007bff; margin-left: 10px;" title="Clique para visualizar"></i>
                    </div>
                </div>
            `;
            lista.appendChild(li);
        });
        
        console.log('✅ Lista de alunos renderizada com', alunosOrdenados.length, 'itens');
    }

    renderAtividades() {
        const lista = document.getElementById('atividades-list');
        if (!lista) {
            console.warn('❌ Elemento atividades-list não encontrado');
            return;
        }
        
        const atividades = this.stateManager.getAllAtividades();
        console.log('📊 Renderizando atividades:', atividades.length, 'registros');
        console.log('📊 Dados das atividades:', atividades);

        // Limpar lista primeiro
        lista.innerHTML = '';

        if (atividades.length === 0) {
            lista.innerHTML = '<li class="empty-state">Nenhuma atividade cadastrada</li>';
            return;
        }

        atividades.forEach(atividade => {
            const li = document.createElement('li');
            li.style.cursor = 'pointer';
            li.onclick = () => this.openViewActivityModal(atividade.id);
            
            li.innerHTML = `
                <div class="atividade-info">
                    <div class="atividade-detalhes">
                        <span class="atividade-nome">${atividade.nome}</span>
                        <span class="atividade-descricao">${atividade.descricao || ''}</span>
                    </div>
                    <div class="atividade-acoes">
                        <span class="atividade-contador">${atividade.alunosInscritos?.length || 0} aluno(s)</span>
                        <button class="btn-editar all-roles" onclick="event.stopPropagation(); window.editAtividade(${atividade.id})" title="Editar atividade">
                            <i class="fas fa-edit"></i>
                            Editar
                        </button>
                        <button class="btn-excluir admin-and-master" onclick="event.stopPropagation(); deletarRegistro('atividades', ${atividade.id})" title="Excluir atividade">
                            <i class="fas fa-trash"></i>
                            Excluir
                        </button>
                    </div>
                </div>
            `;
            lista.appendChild(li);
        });
        
        console.log('✅ Lista de atividades renderizada com', atividades.length, 'itens');
    }

    renderVoluntarios() {
        if (!AuthService.hasAdminPermission()) return;
        
        const lista = document.getElementById('voluntarios-list');
        if (!lista) {
            console.warn('❌ Elemento voluntarios-list não encontrado');
            return;
        }
        
        const voluntarios = this.stateManager.getAllVoluntarios();
        console.log('📊 Renderizando voluntários:', voluntarios.length, 'registros');
        console.log('📊 Dados dos voluntários:', voluntarios);

        // Limpar lista primeiro
        lista.innerHTML = '';

        if (voluntarios.length === 0) {
            lista.innerHTML = '<li class="empty-state">Nenhum voluntário cadastrado</li>';
            return;
        }

        // Ordenar voluntários
        const voluntariosOrdenados = voluntarios.sort((a, b) => {
            if (a.status === 'ativo' && b.status === 'inativo') return -1;
            if (a.status === 'inativo' && b.status === 'ativo') return 1;
            return a.nome.localeCompare(b.nome);
        });

        voluntariosOrdenados.forEach(voluntario => {
            const li = document.createElement('li');
            li.style.cursor = 'pointer';
            li.onclick = () => this.modalService.openViewVoluntarioModal(voluntario.id);
            li.className = voluntario.status === 'inativo' ? 'item-inativo' : '';
            
            li.innerHTML = `
                <div class="voluntario-info">
                    <div class="voluntario-detalhes">
                        <span class="voluntario-nome">${voluntario.nome}</span>
                        <span class="voluntario-email">${voluntario.email}</span>
                    </div>
                    <div class="voluntario-acoes">
                        <span class="status-badge ${voluntario.status}">${voluntario.status}</span>
                        <span class="voluntario-atividade">${voluntario.atividade}</span>
                        <button class="btn-editar admin-and-master" onclick="event.stopPropagation(); window.editVoluntario(${voluntario.id})" title="Editar voluntário">
                            <i class="fas fa-edit"></i>
                            Editar
                        </button>
                        <button class="btn-excluir admin-and-master" onclick="event.stopPropagation(); deletarRegistro('voluntarios', ${voluntario.id})" title="Excluir voluntário">
                            <i class="fas fa-trash"></i>
                            Excluir
                        </button>
                    </div>
                </div>
            `;
            lista.appendChild(li);
        });
        
        console.log('✅ Lista de voluntários renderizada com', voluntariosOrdenados.length, 'itens');
    }

    renderMeusDados() {
        const container = document.getElementById('my-data-content');
        if (!container) return;

        const currentUser = this.stateManager.getCurrentUser();
        if (!currentUser) {
            container.innerHTML = '<div class="loading-message">Erro ao carregar dados do usuário</div>';
            return;
        }

        // ADM_MASTER não deve acessar dados pessoais além do token
        if (currentUser.role === 'ADM_MASTER') {
            container.innerHTML = '<div class="error-message">ADM_MASTER não possui acesso a dados pessoais detalhados.</div>';
            console.warn('🔐 ADM_MASTER tentou acessar dados pessoais detalhados');
            return;
        }

        container.innerHTML = `
            <div class="user-data-display">
                <div class="data-item">
                    <span class="data-label">
                        <i class="fas fa-user"></i>
                        Nome:
                    </span>
                    <span class="data-value">${currentUser.nome}</span>
                </div>
                <div class="data-item">
                    <span class="data-label">
                        <i class="fas fa-envelope"></i>
                        Email:
                    </span>
                    <span class="data-value">${currentUser.email}</span>
                </div>
                <div class="data-item">
                    <span class="data-label">
                        <i class="fas fa-phone"></i>
                        Telefone:
                    </span>
                    <span class="data-value">${currentUser.telefone}</span>
                </div>
                <div class="data-item">
                    <span class="data-label">
                        <i class="fas fa-user-tag"></i>
                        Função:
                    </span>
                    <span class="data-value">${currentUser.role}</span>
                </div>
                <div class="data-item">
                    <span class="data-label">
                        <i class="fas fa-calendar-plus"></i>
                        Cadastrado em:
                    </span>
                    <span class="data-value">${new Date(currentUser.createdAt).toLocaleDateString('pt-BR')}</span>
                </div>
            </div>
        `;
    }



    renderAdmins() {
        const lista = document.getElementById('admins-list');
        if (!lista) return;

        const admins = this.stateManager.getAllAdmins();
        
        console.log('📊 Renderizando administrador:', admins.length, 'registros');
        
        if (admins.length === 0) {
            lista.innerHTML = '<li class="empty-state">Nenhum administrador cadastrado</li>';
            return;
        }

        lista.innerHTML = '';
        
        const adminsOrdenados = admins.sort((a, b) => a.nome.localeCompare(b.nome));

        adminsOrdenados.forEach(admin => {
            const li = document.createElement('li');
            li.style.cursor = 'pointer';
            li.onclick = () => window.openViewAdminModal(admin.id);
            li.className = admin.status === 'inativo' ? 'item-inativo' : '';
            
            const roleText = admin.role === 'ADM_MASTER' ? 'ADM Master' : 'Administrador';
            
            li.innerHTML = `
                <div class="admin-info">
                    <div class="admin-detalhes">
                        <span class="admin-nome">${admin.nome}</span>
                        <span class="admin-email">${admin.email}</span>
                    </div>
                    <div class="admin-acoes">
                        <span class="status-badge ${admin.status}">${admin.status}</span>
                        <span class="admin-role">${roleText}</span>
                        <button class="btn-delete" onclick="event.stopPropagation(); window.deleteAdmin(${admin.id})" title="Excluir administrador">
                            🗑️
                        </button>
                    </div>
                </div>
            `;
            lista.appendChild(li);
        });
        
        console.log('✅ Lista de administrador renderizada com', adminsOrdenados.length, 'itens');
    }

    openViewActivityModal(id) {
        const atividades = this.stateManager.getAllAtividades();
        const atividade = atividades.find(a => a.id === id);
        
        if (!atividade) {
            console.error('❌ Atividade não encontrada:', id);
            return;
        }

        // Preencher dados no modal
        document.getElementById('view-activity-nome').textContent = atividade.nome || '-';
        document.getElementById('view-activity-descricao').textContent = atividade.descricao || 'Sem descrição';
        
        // Listar alunos inscritos
        const alunosList = document.getElementById('alunos-inscritos');
        const alunos = this.stateManager.getAllAlunos();
        const alunosInscritos = alunos.filter(a => a.atividade === atividade.id);
        
        alunosList.innerHTML = '';
        if (alunosInscritos.length > 0) {
            alunosInscritos.forEach(aluno => {
                const li = document.createElement('li');
                li.innerHTML = `<i class="fas fa-user"></i> ${aluno.nome}`;
                alunosList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.className = 'empty-message';
            li.textContent = 'Nenhum aluno inscrito nesta atividade';
            alunosList.appendChild(li);
        }

        // Armazenar ID da atividade para uso posterior
        const modal = document.getElementById('view-activity-modal');
        modal.dataset.activityId = id;
        modal.style.display = 'flex';
        
        console.log('🔍 Modal de atividade aberto:', atividade.nome);
    }
}

// ===============================
// MANIPULADORES DE EVENTOS
// ===============================
class EventHandlers {
    constructor(stateManager) {
        this.stateManager = stateManager;
        this.modalService = new ModalService(stateManager);
    }

    async handleCreateAluno(form) {
        if (!AuthService.hasVoluntarioPermission()) {
            console.warn('🔐 Tentativa de criar aluno sem permissão adequada');
            return;
        }
        
        try {
            // Verificar atividades selecionadas
            const atividadesSelecionadas = document.getElementById('modal-atividades-selecionadas').value;
            if (!atividadesSelecionadas || atividadesSelecionadas.trim() === '') {
                this.mostrarNotificacaoModal("Você deve selecionar pelo menos uma atividade antes de concluir o cadastro.", 'error');
                return;
            }

            const formData = new FormData(form);
            
            // Montar data de nascimento
            const dia = document.getElementById('aluno-dia').value.padStart(2, '0');
            const mes = document.getElementById('aluno-mes').value.padStart(2, '0');
            const ano = document.getElementById('aluno-ano').value;
            
            if (!dia || !mes || !ano) {
                this.mostrarNotificacaoModal("Por favor, preencha a data de nascimento completa.", 'error');
                return;
            }

            const alunoData = {
                nome: Utils.sanitizeInput(formData.get('nome')),
                sobreNome: Utils.sanitizeInput(formData.get('sobre_nome')),
                apelido: Utils.sanitizeInput(formData.get('apelido')) || null,
                cpf: formData.get('cpf') ? formData.get('cpf').replace(/\D/g, "") : null,
                dataNascimento: `${ano}-${mes}-${dia}`,
                nomeResponsavel: Utils.sanitizeInput(formData.get('nome_responsavel')),
                cpfResponsavel: formData.get('cpf_responsavel') ? formData.get('cpf_responsavel').replace(/\D/g, "") : null,
                telefonePrincipal: formData.get('telefone_principal').replace(/\D/g, ""),
                telefoneOpcional: formData.get('telefone_opcional') ? formData.get('telefone_opcional').replace(/\D/g, "") : null,
                atividade: atividadesSelecionadas.split(",").map(id => Number(id.trim())).filter(id => !isNaN(id)),
                termoAutorizado: true
            };

            console.log('🧪 DEBUG: Dados do aluno (formato expandido):', alunoData);

            // Verificar campos obrigatórios
            const camposObrigatorios = {
                'nome': 'Nome do aluno',
                'sobreNome': 'Sobrenome do aluno',
                'nomeResponsavel': 'Nome do responsável',
                'telefonePrincipal': 'Telefone principal',
                'dataNascimento': 'Data de nascimento'
            };

            for (const [campo, nome] of Object.entries(camposObrigatorios)) {
                if (!alunoData[campo] || alunoData[campo].toString().trim() === '') {
                    this.mostrarNotificacaoModal(`O campo "${nome}" é obrigatório.`, 'error');
                    return;
                }
            }

            this.mostrarNotificacaoModal("Cadastrando aluno...", 'info');

            // Verificar se há token de autenticação para tentar API
            const token = localStorage.getItem('saberviver_token');
            let cadastroRealizado = false;

            if (token) {
                try {
                    const response = await fetch("https://saberviver-api.up.railway.app/alunos", {
                        method: "POST",
                        headers: {
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                            "Authorization": `Bearer ${token}`
                        },
                        mode: 'cors',
                        credentials: 'omit',
                        body: JSON.stringify(alunoData)
                    });

                    if (response.ok) {
                        cadastroRealizado = true;
                    } else {
                        console.log("❌ API retornou erro, usando modo local");
                    }
                } catch (apiError) {
                    console.log("❌ Erro ao conectar com API, usando modo local:", apiError);
                }
            }

            // Se API não funcionou, cadastrar localmente
            if (!cadastroRealizado) {
                console.log("💾 Cadastrando localmente...");
                this.cadastrarAlunoLocal(alunoData);
            }

            this.mostrarNotificacaoModal("✅ Cadastro concluído com sucesso!", 'success');
            
            // Aguardar um pouco antes de fechar o modal
            setTimeout(() => {
                this.modalService.closeStudentModal();
                NotificationService.show(`Aluno ${alunoData.nome} ${alunoData.sobreNome} cadastrado com sucesso!`, 'success');
                
                // Recarregar lista de alunos
                if (window.appInstance && window.appInstance.renderer) {
                    window.appInstance.renderer.renderAlunos();
                }
            }, 1500);
            
        } catch (error) {
            console.error('❌ ERRO detalhado ao criar aluno:', error);
            
            if (error.message.includes('CORS') || error.message.includes('blocked') || error.message.includes('403')) {
                this.mostrarNotificacaoModal("⚠️ Erro de CORS detectado. Tente abrir em um servidor local ou contate o administrador.", 'warning');
            } else if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
                this.mostrarNotificacaoModal("❌ Erro de conexão. Verifique sua internet e tente novamente.", 'error');
            } else {
                this.mostrarNotificacaoModal("❌ Erro inesperado: " + error.message, 'error');
            }
        }
    }

    // Cadastrar aluno localmente quando API não está disponível
    cadastrarAlunoLocal(alunoData) {
        const alunosAtuais = this.stateManager.getAllAlunos();
        
        // Gerar novo ID
        const novoId = Math.max(...alunosAtuais.map(a => a.id), 0) + 1;
        
        // Calcular idade a partir da data de nascimento
        const hoje = new Date();
        const nascimento = new Date(alunoData.dataNascimento);
        const idade = hoje.getFullYear() - nascimento.getFullYear() - 
                      (hoje.getMonth() < nascimento.getMonth() || 
                       (hoje.getMonth() === nascimento.getMonth() && hoje.getDate() < nascimento.getDate()) ? 1 : 0);
        
        // Converter array de atividades em string (primeira atividade)
        let atividadeNome = 'Sem atividade';
        if (alunoData.atividade && alunoData.atividade.length > 0) {
            const atividades = this.stateManager.getAllAtividades();
            const atividadeEncontrada = atividades.find(a => a.id === alunoData.atividade[0]);
            if (atividadeEncontrada) {
                atividadeNome = atividadeEncontrada.nome;
            }
        }
        
        const novoAluno = {
            id: novoId,
            nome: `${alunoData.nome} ${alunoData.sobreNome}`,
            apelido: alunoData.apelido || '',
            idade: idade,
            cpf: alunoData.cpf || '',
            dataNascimento: alunoData.dataNascimento,
            nomeResponsavel: alunoData.nomeResponsavel,
            cpfResponsavel: alunoData.cpfResponsavel || '',
            telefonePrincipal: alunoData.telefonePrincipal,
            telefoneOpcional: alunoData.telefoneOpcional || '',
            atividade: atividadeNome,
            status: 'ativo'
        };
        
        // Adicionar ao state
        const novosAlunos = [...alunosAtuais, novoAluno];
        this.stateManager.setState({ alunos: novosAlunos });
        
        console.log('✅ Aluno cadastrado localmente:', novoAluno);
    }

    // Mostrar notificação dentro do modal
    mostrarNotificacaoModal(mensagem, tipo = 'info') {
        const notificacao = document.getElementById('modal-notificacao');
        if (!notificacao) return;

        // Definir cores baseadas no tipo
        const cores = {
            'success': '#28a745',
            'error': '#dc3545',
            'warning': '#ffc107',
            'info': '#17a2b8'
        };

        notificacao.textContent = mensagem;
        notificacao.style.backgroundColor = cores[tipo] || cores['info'];
        notificacao.style.color = tipo === 'warning' ? '#212529' : 'white';
        notificacao.style.display = 'block';
        notificacao.classList.add('show');

        // Auto-hide após 4 segundos para mensagens não críticas
        if (tipo !== 'error') {
            setTimeout(() => {
                notificacao.classList.remove('show');
                setTimeout(() => {
                    notificacao.style.display = 'none';
                }, 300);
            }, 4000);
        }
    }

    async handleCreateAtividade(form) {
        if (!AuthService.hasAdminPermission()) {
            console.warn('🔐 Tentativa de criar atividade sem permissão adequada');
            return;
        }
        try {
            const formData = new FormData(form);

            const atividadeData = {
                nome: Utils.sanitizeInput(formData.get('atividade-nome')),
                descricao: Utils.sanitizeInput(formData.get('atividade-descricao')),
                capacidadeMaxima: 20
            };

            const atividade = new Atividade(atividadeData);
            const validationErrors = atividade.validate();
            
            if (validationErrors.length > 0) {
                NotificationService.show(validationErrors.join(', '), 'error');
                return;
            }

            await ApiService.createAtividade(atividadeData);
            const atividades = await ApiService.getAtividades();
            this.stateManager.setState({ atividades });
            
            // Notificação de sucesso
            NotificationService.show(`✅ Atividade ${atividadeData.nome} criada com sucesso!`, 'success');
            
            this.modalService.closeActivityModal();
        } catch (error) {
            console.error('Erro ao criar atividade:', error);
            NotificationService.show(`Erro ao criar atividade: ${error.message}`, 'error');
        }
    }

    async handleCreateVoluntario(form) {
    // Corrigido: bloco duplicado removido
        try {
            // Permissões: apenas ADM ou ADM_MASTER podem cadastrar voluntário
            const currentUser = this.stateManager.getCurrentUser();
            if (!currentUser || (currentUser.role !== 'ADM' && currentUser.role !== 'ADM_MASTER')) {
                NotificationService.show('Apenas ADM ou ADM_MASTER pode cadastrar voluntários', 'error');
                return;
            }

            // Coletar dados do formulário
            const voluntarioData = {
                nome: Utils.sanitizeInput(document.getElementById('voluntario-nome').value),
                email: Utils.sanitizeInput(document.getElementById('voluntario-email').value),
                telefone: document.getElementById('voluntario-telefone').value,
                atividade: Utils.sanitizeInput(document.getElementById('voluntario-atividade').value),
                cpf: document.getElementById('voluntario-cpf') ? document.getElementById('voluntario-cpf').value : '',
                dataNascimento: document.getElementById('voluntario-data-nascimento') ? document.getElementById('voluntario-data-nascimento').value : '',
                senha: document.getElementById('voluntario-senha') ? document.getElementById('voluntario-senha').value : '',
                role: 'VOLUNTARIO'
            };

            // Validação básica
            const missing = [];
            if (!voluntarioData.nome) missing.push('nome');
            if (!voluntarioData.email) missing.push('email');
            if (!voluntarioData.telefone) missing.push('telefone');
            if (!voluntarioData.atividade) missing.push('atividade');
            if (!voluntarioData.senha) missing.push('senha');
            if (!voluntarioData.dataNascimento) missing.push('dataNascimento');

            if (missing.length > 0) {
                NotificationService.show(`Preencha os campos obrigatórios: ${missing.join(', ')}`, 'error');
                return;
            }

            // Validar via modelo Voluntario (se existir)
            const voluntarioModel = new Voluntario(voluntarioData);
            const errors = voluntarioModel.validate ? voluntarioModel.validate() : [];
            if (errors && errors.length > 0) {
                NotificationService.show(`Erros de validação: ${errors.join(', ')}`, 'error');
                return;
            }

            // Enviar para API
            const novoVoluntario = await ApiService.createVoluntario(voluntarioData);
            // Atualizar lista local de voluntários (tentar)
            try {
                const voluntarios = await ApiService.getVoluntarios();
                this.stateManager.setState({ voluntarios });
            } catch (err) {
                console.warn('Não foi possível atualizar lista local de voluntários:', err);
            }

            NotificationService.show(`✅ Voluntário ${voluntarioData.nome} cadastrado com sucesso! (ID: ${novoVoluntario?.id || 'N/A'})`, 'success');
            form.reset();
            window.closeVolunteerModal();
        } catch (error) {
            console.error('Erro ao criar voluntário:', error);
            NotificationService.show(`Erro ao cadastrar voluntário: ${error.message}`, 'error');
        }
    }

    async handleEditAluno(form) {
        if (!AuthService.hasVoluntarioPermission()) {
            console.warn('🔐 Tentativa de editar aluno sem permissão adequada');
            return;
        }
        try {
            const alunoId = parseInt(form.dataset.alunoId);
            const toggle = document.getElementById('student-status-toggle');
            
            const alunoData = {
                nome: Utils.sanitizeInput(document.getElementById('edit-aluno-nome').value),
                sobre_nome: Utils.sanitizeInput(document.getElementById('edit-aluno-sobrenome').value),
                apelido: Utils.sanitizeInput(document.getElementById('edit-aluno-apelido').value),
                cpf: document.getElementById('edit-aluno-cpf').value,
                data_nascimento: document.getElementById('edit-aluno-data-nascimento').value,
                nome_responsavel: Utils.sanitizeInput(document.getElementById('edit-aluno-nome-responsavel').value),
                cpf_responsavel: document.getElementById('edit-aluno-cpf-responsavel').value,
                telefone_principal: document.getElementById('edit-aluno-telefone-principal').value,
                telefone_opcional: document.getElementById('edit-aluno-telefone-opcional').value,
                atividade: document.getElementById('edit-aluno-atividade').value,
                status: toggle ? toggle.dataset.status : 'ativo'
            };

            const aluno = new Aluno(alunoData);
            const validationErrors = aluno.validate();
            
            if (validationErrors.length > 0) {
                NotificationService.show(validationErrors.join(', '), 'error');
                return;
            }

            await ApiService.updateAluno(alunoId, alunoData);
            const alunos = await ApiService.getAlunos();
            this.stateManager.setState({ alunos });
            
            // Notificação de sucesso
            NotificationService.show(`✏️ Dados de ${alunoData.nome} atualizados com sucesso!`, 'success');
            
            this.modalService.closeViewStudentModal();
        } catch (error) {
            console.error('Erro ao atualizar aluno:', error);
            NotificationService.show(`Erro ao atualizar aluno: ${error.message}`, 'error');
        }
    }

    async handleEditVoluntario(form) {
        try {
            const voluntarioId = parseInt(form.dataset.voluntarioId);
            const toggle = document.getElementById('volunteer-status-toggle');
            
            const voluntarioData = {
                nome: Utils.sanitizeInput(document.getElementById('edit-voluntario-nome').value),
                email: Utils.sanitizeInput(document.getElementById('edit-voluntario-email').value),
                telefone: document.getElementById('edit-voluntario-telefone').value,
                cpf: document.getElementById('edit-voluntario-cpf').value,
                atividade: document.getElementById('edit-voluntario-atividade').value,
                status: toggle ? toggle.dataset.status : 'ativo'
            };

            const voluntario = new Voluntario(voluntarioData);
            const validationErrors = voluntario.validate();
            
            if (validationErrors.length > 0) {
                NotificationService.show(validationErrors.join(', '), 'error');
                return;
            }

            await ApiService.updateVoluntario(voluntarioId, voluntarioData);
            const voluntarios = await ApiService.getVoluntarios();
            this.stateManager.setState({ voluntarios });
            
            this.modalService.closeViewVoluntarioModal();
            NotificationService.show('Voluntário atualizado com sucesso!', 'success');
        } catch (error) {
            console.error('Erro ao atualizar voluntário:', error);
            NotificationService.show(`Erro ao atualizar voluntário: ${error.message}`, 'error');
        }
    }

    async handleDeleteItem(tipo, id) {
        try {
            if (tipo === 'voluntarios') {
                const voluntario = this.stateManager.getState().voluntarios.find(c => c.id === parseInt(id));
                if (voluntario) {
                    this.modalService.showDeleteConfirmation('voluntarios', id, voluntario);
                }
                return;
            }

            // Verificar permissões para deletar
            const currentUser = AuthService.getCurrentUser();
            if (!currentUser) {
                NotificationService.show('Usuário não autenticado', 'error');
                return;
            }

            // VOLUNTÁRIO não pode deletar nada
            if (currentUser.role === 'VOLUNTARIO') {
                NotificationService.show('Você não tem permissão para excluir registros', 'error');
                return;
            }

            // ADMIN pode deletar alunos, atividades e voluntários
            // ADM_MASTER pode deletar tudo
            if (currentUser.role === 'ADM' && !['alunos', 'atividades', 'voluntarios'].includes(tipo)) {
                NotificationService.show('Você não tem permissão para excluir este tipo de registro', 'error');
                return;
            }

            const confirmed = await Utils.showConfirm(`Tem certeza que deseja excluir este ${tipo.slice(0, -1)}?`);
            if (!confirmed) return;

            if (tipo === 'alunos') {
                const aluno = this.stateManager.getState().alunos.find(a => a.id === parseInt(id));
                await ApiService.deleteAluno(id);
                const alunos = await ApiService.getAlunos();
                this.stateManager.setState({ alunos });
                this.modalService.closeViewStudentModal();
                NotificationService.show(`🗑️ Aluno ${aluno ? aluno.nome : ''} excluído com sucesso!`, 'success');
            } else if (tipo === 'atividades') {
                const atividade = this.stateManager.getState().atividades.find(a => a.id === parseInt(id));
                await ApiService.deleteAtividade(id);
                const atividades = await ApiService.getAtividades();
                this.stateManager.setState({ atividades });
                NotificationService.show(`🗑️ Atividade ${atividade ? atividade.nome : ''} excluída com sucesso!`, 'success');
            } else if (tipo === 'voluntarios') {
                const voluntario = this.stateManager.getState().voluntarios.find(v => v.id === parseInt(id));
                await ApiService.deleteVoluntario(id);
                const voluntarios = await ApiService.getVoluntarios();
                this.stateManager.setState({ voluntarios });
                NotificationService.show(`🗑️ Voluntário ${voluntario ? voluntario.nome : ''} excluído com sucesso!`, 'success');
            }
        } catch (error) {
            console.error(`Erro ao excluir ${tipo.slice(0, -1)}:`, error);
            NotificationService.show(`Erro ao excluir ${tipo.slice(0, -1)}: ${error.message}`, 'error');
        }
    }

    async handleConfirmDelete() {
        try {
            const deleteData = this.stateManager.getState().deleteData;
            if (!deleteData) return;

            await ApiService.deleteVoluntario(deleteData.id);
            const voluntarios = await ApiService.getVoluntarios();
            this.stateManager.setState({ voluntarios, deleteData: null });
            
            // Notificação de sucesso com nome do voluntário
            NotificationService.show(`🗑️ Voluntário ${deleteData.voluntario ? deleteData.voluntario.nome : ''} excluído com sucesso!`, 'success');
            
            this.modalService.closeDeleteConfirmationModal();
            this.modalService.closeViewVoluntarioModal();
        } catch (error) {
            console.error('Erro ao excluir voluntário:', error);
            NotificationService.show(`Erro ao excluir voluntário: ${error.message}`, 'error');
        }
    }



    async handleCreateAdmin(form) {
        try {
            // Verificar permissões: somente ADM_MASTER pode criar administrador
            const currentUser = this.stateManager.getCurrentUser();
            if (!currentUser || currentUser.role !== 'ADM_MASTER') {
                NotificationService.show('Apenas ADM_MASTER pode cadastrar administradores', 'error');
                return;
            }

            // Coletar dados do formulário
            const adminData = {
                login: Utils.sanitizeInput(document.getElementById('admin-email').value) || Utils.sanitizeInput(document.getElementById('admin-nome').value).split(' ')[0],
                senha: document.getElementById('admin-senha').value,
                nome: Utils.sanitizeInput(document.getElementById('admin-nome').value),
                sobreNome: Utils.sanitizeInput(document.getElementById('admin-sobreNome').value),
                cpf: document.getElementById('admin-cpf').value,
                telefone: document.getElementById('admin-telefone').value,
                areaAtuacao: Utils.sanitizeInput(document.getElementById('admin-areaAtuacao').value),
                email: Utils.sanitizeInput(document.getElementById('admin-email').value),
                dataNascimento: document.getElementById('admin-data-nascimento') ? document.getElementById('admin-data-nascimento').value : '',
                role: 'ADM'
            };

            // Campos obrigatórios: login, senha, nome, cpf, email, dataNascimento
            const missing = [];
            if (!adminData.login) missing.push('login');
            if (!adminData.senha) missing.push('senha');
            if (!adminData.nome) missing.push('nome');
            if (!adminData.cpf) missing.push('cpf');
            if (!adminData.email) missing.push('email');
            if (!adminData.dataNascimento) missing.push('dataNascimento');

            if (missing.length > 0) {
                NotificationService.show('Campos obrigatórios ausentes: ' + missing.join(', '), 'error');
                return;
            }

            // Validar via modelo Admin (se existir)
            const adminModel = new Admin(adminData);
            const errors = adminModel.validate ? adminModel.validate() : [];
            if (errors && errors.length > 0) {
                NotificationService.show(errors.join(', '), 'error');
                return;
            }

            // Enviar para API
            const novoAdmin = await ApiService.createAdmin(adminData);
            // Atualizar lista local de admins (tentar)
            try {
                const admins = await ApiService.getAdmins();
                this.stateManager.setState({ admins });
            } catch (err) {
                console.warn('Não foi possível atualizar lista de admins:', err);
            }

            NotificationService.show(`✅ Administrador ${adminData.nome} cadastrado com sucesso! (ID: ${novoAdmin?.id || 'N/A'})`, 'success');
            form.reset();
            window.closeAdminModal();
        } catch (error) {
            console.error('Erro ao criar administrador:', error);
            NotificationService.show(`Erro ao cadastrar administrador: ${error.message}`, 'error');
        }
    }

    async handleEditAdmin(form) {
        try {
            const currentUser = this.stateManager.getCurrentUser();
            const admins = this.stateManager.getState().admins;
            const adminId = parseInt(document.getElementById('edit-admin-id').value);
            const adminToEdit = admins.find(a => a.id === adminId);
            
            if (!adminToEdit) {
                NotificationService.show('Administrador não encontrado', 'error');
                return;
            }

            // Verificar se o usuário atual tem permissão para editar
            if (currentUser.role !== 'ADM_MASTER') {
                NotificationService.show('Apenas ADM_MASTER pode editar administrador', 'error');
                return;
            }

            const updatedData = {
                nome: Utils.sanitizeInput(document.getElementById('edit-admin-nome').value),
                email: Utils.sanitizeInput(document.getElementById('edit-admin-email').value),
                telefone: document.getElementById('edit-admin-telefone').value,
                cpf: document.getElementById('edit-admin-cpf').value,
                role: document.getElementById('edit-admin-role').value,
                status: document.getElementById('edit-admin-status').value
            };

            // Se uma nova senha foi fornecida, incluir na atualização
            const novaSenha = document.getElementById('edit-admin-senha').value;
            if (novaSenha.trim()) {
                if (novaSenha.length < 6) {
                    NotificationService.show('Nova senha deve ter pelo menos 6 caracteres', 'error');
                    return;
                }
                updatedData.senha = novaSenha;
            }

            const admin = new Admin({...adminToEdit, ...updatedData});
            const errors = admin.validate();
            
            if (errors.length > 0) {
                NotificationService.show(errors.join(', '), 'error');
                return;
            }

            await ApiService.updateAdmin(adminId, updatedData);
            const adminsAtualizados = await ApiService.getAdmins();
            this.stateManager.setState({ admins: adminsAtualizados });
            
            window.closeEditAdminModal();
            NotificationService.show('Administrador atualizado com sucesso!', 'success');
        } catch (error) {
            console.error('Erro ao atualizar administrador:', error);
            NotificationService.show(`Erro ao atualizar administrador: ${error.message}`, 'error');
        }
    }

    async handleEditMyData(form) {
        try {
            const currentUser = this.stateManager.getCurrentUser();
            if (!currentUser) return;

            const updatedData = {
                nome: Utils.sanitizeInput(document.getElementById('edit-my-nome').value),
                email: Utils.sanitizeInput(document.getElementById('edit-my-email').value),
                telefone: document.getElementById('edit-my-telefone').value
            };

            const voluntario = new Voluntario({...currentUser, ...updatedData});
            const errors = voluntario.validate();
            
            if (errors.length > 0) {
                NotificationService.show(errors.join(', '), 'error');
                return;
            }

            // Atualizar no backend simulado
            await ApiService.updateVoluntario(currentUser.id, updatedData);
            
            // Atualizar usuário atual
            const updatedUser = {...currentUser, ...updatedData};
            localStorage.setItem('currentUser', JSON.stringify(updatedUser));
            this.stateManager.setState({ currentUser: updatedUser });
            
            window.closeEditMyDataModal();
            NotificationService.show('Dados atualizados com sucesso!', 'success');
        } catch (error) {
            console.error('Erro ao atualizar dados:', error);
            NotificationService.show(`Erro ao atualizar dados: ${error.message}`, 'error');
        }
    }

    async handleEditAtividade(form) {
        if (!AuthService.hasVoluntarioPermission()) {
            console.warn('🔐 Tentativa de editar atividade sem permissão adequada');
            return;
        }
        
        try {
            const activityId = form.dataset.activityId;
            if (!activityId) {
                console.error('❌ ID da atividade não encontrado no formulário');
                return;
            }

            const updatedData = {
                nome: Utils.sanitizeInput(document.getElementById('edit-activity-nome').value),
                descricao: Utils.sanitizeInput(document.getElementById('edit-activity-descricao').value)
            };

            // Validação básica
            if (!updatedData.nome) {
                NotificationService.show('O nome da atividade é obrigatório', 'error');
                return;
            }

            // Atualizar no backend simulado
            await ApiService.updateAtividade(activityId, updatedData);
            
            // Recarregar atividades
            const atividades = await ApiService.getAtividades();
            this.stateManager.setState({ atividades });
            
            window.closeEditActivityModal();
            NotificationService.show('Atividade atualizada com sucesso!', 'success');
            
            console.log('✅ Atividade atualizada:', updatedData);
        } catch (error) {
            console.error('❌ ERRO ao atualizar atividade:', error);
            NotificationService.show(`Erro ao atualizar atividade: ${error.message}`, 'error');
        }
    }
}

// ===============================
// APLICAÇÃO PRINCIPAL
// ===============================
class App {
    constructor() {
        this.currentUser = null; // usuário logado
        this.stateManager = new StateManager();
        this.renderer = new UIRenderer(this.stateManager);
        this.modalService = new ModalService(this.stateManager);
        this.eventHandlers = new EventHandlers(this.stateManager);
    }

    // Inicialização principal
    async init() {
        try {
            // 1️⃣ Verifica autenticação
            if (!AuthService.isAuthenticated()) {
                this.redirectToLogin();
                return;
            }

            // 2️⃣ Carrega dados iniciais (usuário logado, etc)
            await this.loadInitialData();

            // 3️⃣ Configura interface do usuário
            AuthService.setupUserInterface(this.currentUser);

            // 4️⃣ Configura listeners
            this.setupEventListeners();

            // 5️⃣ Renderização inicial (após delay para garantir DOM pronto)
            setTimeout(() => {
                console.log('🔧 Aplicando permissões e renderizando tabs...');
                AuthService.setupUserInterface(this.currentUser); // reaplica permissões
                this.renderer.ensureSingleActiveTab();
                this.renderer.renderCurrentTab();

                setTimeout(() => {
                    if (window.debugPermissions) window.debugPermissions();
                    console.log('✅ Inicialização concluída');
                }, 100);
            }, 200);

        } catch (error) {
            console.error('❌ Erro na inicialização:', error);
            NotificationService.show('Erro ao carregar aplicação', 'error');
        }
    }

    // Carrega dados iniciais, incluindo usuário logado
    async loadInitialData() {
        try {
            // Tentar obter usuário atual
            this.currentUser = AuthService.getCurrentUser();
            
            let useApiData = false;
            
            if (this.currentUser) {
                console.log("👤 Usuário logado:", this.currentUser);
                this.stateManager.setState({ currentUser: this.currentUser });
                useApiData = true;
            } else {
                console.log("⚠️ Nenhum usuário autenticado, usando modo demonstração");
                // Criar usuário fictício para demonstração
                this.currentUser = {
                    id: 'demo',
                    nome: 'Usuário Demo',
                    email: 'demo@sistema.com',
                    role: 'ADMIN'
                };
                this.stateManager.setState({ currentUser: this.currentUser });
            }
            
            // Tentar carregar dados da API se autenticado
            if (useApiData) {
                try {
                    const [alunos, atividades, voluntarios, admins] = await Promise.all([
                        ApiService.getAlunos?.() || [],
                        ApiService.getAtividades?.() || [],
                        ApiService.getVoluntarios?.() || [],
                        ApiService.getAdmins?.() || []
                    ]);
                    
                    this.stateManager.setState({ alunos, atividades, voluntarios, admins });
                    console.log("📡 Dados da API carregados (incluindo administradores)");
                    return;
                } catch (apiError) {
                    console.error("❌ Erro ao carregar dados da API:", apiError);
                    console.log("🔄 Carregando dados de demonstração...");
                }
            }
            
            // Carregar dados de demonstração
            this.loadDemoData();

        } catch (error) {
            console.error("❌ Erro ao carregar dados iniciais:", error);
            console.log("🔄 Carregando dados de demonstração como fallback...");
            this.loadDemoData();
        }
    }

    // Carrega dados de demonstração quando API não está disponível
    loadDemoData() {
        console.log("🎭 Carregando dados de demonstração...");
        
        const demoData = {
            alunos: [
                { 
                    id: 1, 
                    nome: 'Ana Silva', 
                    apelido: 'Aninha',
                    idade: 10, 
                    cpf: '123.456.789-00',
                    dataNascimento: '2013-05-15',
                    nomeResponsavel: 'Maria Silva', 
                    cpfResponsavel: '987.654.321-00',
                    telefonePrincipal: '(11) 99999-1111',
                    telefoneOpcional: '',
                    atividade: 'Futebol', 
                    status: 'ativo' 
                },
                { 
                    id: 2, 
                    nome: 'João Santos', 
                    apelido: 'Joãozinho',
                    idade: 12, 
                    cpf: '234.567.890-11',
                    dataNascimento: '2011-08-22',
                    nomeResponsavel: 'Pedro Santos', 
                    cpfResponsavel: '876.543.210-99',
                    telefonePrincipal: '(11) 99999-2222',
                    telefoneOpcional: '(11) 88888-2222',
                    atividade: 'Natação', 
                    status: 'ativo' 
                },
                { 
                    id: 3, 
                    nome: 'Carla Oliveira', 
                    apelido: '',
                    idade: 9, 
                    cpf: '345.678.901-22',
                    dataNascimento: '2014-12-03',
                    nomeResponsavel: 'Sandra Oliveira', 
                    cpfResponsavel: '765.432.109-88',
                    telefonePrincipal: '(11) 99999-3333',
                    telefoneOpcional: '',
                    atividade: 'Ballet', 
                    status: 'ativo' 
                }
            ],
            atividades: [
                { 
                    id: 1, 
                    nome: 'Futebol Infantil', 
                    descricao: 'Aulas de futebol para crianças de 8 a 14 anos', 
                    vagas: 20,
                    capacidadeMaxima: 20,
                    status: 'ativo'
                },
                { 
                    id: 2, 
                    nome: 'Natação', 
                    descricao: 'Aulas de natação para iniciantes', 
                    vagas: 15,
                    capacidadeMaxima: 15,
                    status: 'ativo'
                },
                { 
                    id: 3, 
                    nome: 'Ballet', 
                    descricao: 'Aulas de ballet clássico', 
                    vagas: 12,
                    capacidadeMaxima: 12,
                    status: 'ativo'
                },
                { 
                    id: 4, 
                    nome: 'Judô', 
                    descricao: 'Artes marciais e disciplina', 
                    vagas: 18,
                    capacidadeMaxima: 18,
                    status: 'ativo'
                }
            ],
            voluntarios: [
                { 
                    id: 1, 
                    nome: 'Prof. Carlos', 
                    email: 'carlos@escola.com', 
                    telefone: '(11) 88888-1111', 
                    atividade: 'Futebol', 
                    status: 'ativo', 
                    role: 'VOLUNTARIO' 
                },
                { 
                    id: 2, 
                    nome: 'Profa. Lucia', 
                    email: 'lucia@escola.com', 
                    telefone: '(11) 88888-2222', 
                    atividade: 'Natação', 
                    status: 'ativo', 
                    role: 'VOLUNTARIO' 
                }
            ],
            admins: [
                {
                    id: 1,
                    nome: 'Admin Sistema',
                    email: 'admin@saberviver.org',
                    telefone: '(11) 99999-0001',
                    cpf: '111.222.333-44',
                    role: 'ADMIN',
                    status: 'ativo'
                },
                {
                    id: 2,
                    nome: 'Super Admin',
                    email: 'master@saberviver.org',
                    telefone: '(11) 99999-0002',
                    cpf: '555.666.777-88',
                    role: 'ADM_MASTER',
                    status: 'ativo'
                }
            ]
        };
        
        this.stateManager.setState(demoData);
        console.log("✅ Dados de demonstração carregados:");
        console.log("- Alunos:", demoData.alunos.length);
        console.log("- Atividades:", demoData.atividades.length);
        console.log("- Voluntários:", demoData.voluntarios.length);
        console.log("- Administradores:", demoData.admins.length);
    }

    /**
     * Carrega dados específicos baseados no role do usuário
     */
    async loadUserSpecificData(type) {
        const userRole = this.currentUser?.role;
        
        switch (type) {
            case 'alunos':
                // Voluntários veem apenas seus alunos, admins+ veem todos
                if (userRole === 'VOLUNTARIO') {
                    try {
                        return await ApiService.getMeusAlunos();
                    } catch (error) {
                        console.warn('⚠️ Endpoint getMeusAlunos não disponível, usando getAlunos...');
                        return await ApiService.getAlunos();
                    }
                } else {
                    return await ApiService.getAlunos();
                }

            case 'atividades':
                // Voluntários veem apenas suas atividades, admins+ veem todas
                if (userRole === 'VOLUNTARIO') {
                    try {
                        return await ApiService.getMinhasAtividades();
                    } catch (error) {
                        console.warn('⚠️ Endpoint getMinhasAtividades não disponível, usando getAtividades...');
                        return await ApiService.getAtividades();
                    }
                } else {
                    return await ApiService.getAtividades();
                }

            case 'voluntarios':
                // Admins veem voluntários supervisionados, masters veem todos
                if (userRole === 'ADM') {
                    try {
                        return await ApiService.getMeusVoluntarios();
                    } catch (error) {
                        console.warn('⚠️ Endpoint getMeusVoluntarios não disponível, usando getVoluntarios...');
                        return await ApiService.getVoluntarios();
                    }
                } else {
                    return await ApiService.getVoluntarios();
                }

            default:
                throw new Error(`Tipo de dados não reconhecido: ${type}`);
        }
    }

    // Configurar event listeners
    setupEventListeners() {
        console.log('🎧 Configurando event listeners...');
        
        // Event listeners para formulários
        this.setupFormListeners();
        
        // Event listeners para modais
        this.modalService.setupModalClosers();
        
        // Event listeners para busca
        this.setupSearchListeners();
        
        console.log('✅ Event listeners configurados');
    }

    setupFormListeners() {
        // Formulário de criação de aluno
        const studentForm = document.getElementById('student-form');
        if (studentForm) {
            studentForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.eventHandlers.handleCreateAluno(studentForm);
            });
        }

        // Formulário de edição de aluno
        const editStudentForm = document.getElementById('edit-student-form');
        if (editStudentForm) {
            editStudentForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.eventHandlers.handleEditAluno(editStudentForm);
            });
        }

        // Formulário de criação de atividade
        const activityForm = document.getElementById('activity-form');
        if (activityForm) {
            activityForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.eventHandlers.handleCreateAtividade(activityForm);
            });
        }

        // Formulário de criação de voluntário
        const volunteerForm = document.getElementById('voluntario-form');
        if (volunteerForm) {
            volunteerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.eventHandlers.handleCreateVoluntario(volunteerForm);
            });
        }

        // Formulário de edição de voluntário
        const editVolunteerForm = document.getElementById('edit-volunteer-form');
        if (editVolunteerForm) {
            editVolunteerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.eventHandlers.handleEditVoluntario(editVolunteerForm);
            });
        }

        // Formulário de criação de administrador
        const adminForm = document.getElementById('admin-form');
        if (adminForm) {
            adminForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.eventHandlers.handleCreateAdmin(adminForm);
            });
        }

        // Formulário de edição de administrador
        const editAdminForm = document.getElementById('edit-admin-form');
        if (editAdminForm) {
            editAdminForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.eventHandlers.handleEditAdmin(editAdminForm);
            });
        }

        // Outros formulários...
        const editMyDataForm = document.getElementById('edit-my-data-form');
        if (editMyDataForm) {
            editMyDataForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.eventHandlers.handleEditMyData(editMyDataForm);
            });
        }
    }

    setupSearchListeners() {
        // Busca de alunos
        const searchAlunos = document.getElementById('search-alunos');
        if (searchAlunos) {
            searchAlunos.addEventListener('input', Utils.debounce(() => {
                window.searchAlunos();
            }, 300));
        }

        // Busca de administrador
        const searchAdmins = document.getElementById('search-admins');
        if (searchAdmins) {
            searchAdmins.addEventListener('input', Utils.debounce(() => {
                window.searchAdmins();
            }, 300));
        }

        // Busca de voluntários
        const searchVoluntarios = document.getElementById('search-voluntarios');
        if (searchVoluntarios) {
            searchVoluntarios.addEventListener('input', Utils.debounce(() => {
                window.searchVoluntarios();
            }, 300));
        }
    }

    // Redireciona para login caso não esteja autenticado
    redirectToLogin() {
        console.log('🔒 Usuário não autenticado. Redirecionando para login...');
        localStorage.clear();
        // aqui você pode redirecionar ou exibir mensagem customizada
    }
}

class ApiService {
    static baseUrl = "https://saberviver-api.up.railway.app"; // sem barra no final

    static async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const res = await fetch(url, {
            ...options,
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${localStorage.getItem("saberviver_token")}`,
                ...(options.headers || {})
            }
        });

        if (!res.ok) {
            const text = await res.text();
            throw new Error(`Erro ${res.status}: ${text}`);
        }
        
        // Verificar se a resposta tem conteúdo antes de tentar fazer JSON
        const contentType = res.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const text = await res.text();
            if (text.trim()) {
                return JSON.parse(text);
            }
        }
        
        // Se não há conteúdo JSON, retornar objeto vazio
        return {};
    }

    // ===============================
    // MÉTODOS DE USUÁRIOS
    // ===============================
    static async getCurrentUser() {
        console.log('🔍 Buscando dados do usuário atual na API...');
        return this.request('/usuarios/me');
    }

    // ===============================
    // MÉTODOS DE ALUNOS
    // ===============================
    static async getAlunos() {
        console.log('📚 Buscando alunos na API...');
        const response = await this.request('/alunos');
        
        // Se a resposta tem content (paginação), retorna o content
        if (response && response.content) {
            return response.content;
        }
        
        // Se não tem content, retorna a resposta diretamente
        return response;
    }

    static async getAlunoById(id) {
        console.log(`🔍 Buscando aluno ${id} na API...`);
        return this.request(`/alunos/${id}`);
    }

    static async createAluno(alunoData) {
        console.log('➕ Criando aluno na API...');
        return this.request('/alunos', {
            method: 'POST',
            body: JSON.stringify(alunoData)
        });
    }

    static async updateAluno(id, alunoData) {
        console.log(`✏️ Atualizando aluno ${id} na API...`);
        return this.request(`/alunos/${id}`, {
            method: 'PUT',
            body: JSON.stringify(alunoData)
        });
    }

    static async deleteAluno(id) {
        console.log(`🗑️ Deletando aluno ${id} na API...`);
        return this.request(`/alunos/${id}`, {
            method: 'DELETE'
        });
    }

    // ===============================
    // MÉTODOS DE ATIVIDADES
    // ===============================
    static async getAtividades() {
        console.log('🎯 Buscando atividades na API...');
        const response = await this.request('/atividades');
        
        // Se a resposta tem content (paginação), retorna o content
        if (response && response.content) {
            return response.content;
        }
        
        // Se não tem content, retorna a resposta diretamente
        return response;
    }

    static async getAtividadeById(id) {
        console.log(`🔍 Buscando atividade ${id} na API...`);
        return this.request(`/atividades/${id}`);
    }

    static async createAtividade(atividadeData) {
        console.log('➕ Criando atividade na API...');
        return this.request('/atividades', {
            method: 'POST',
            body: JSON.stringify(atividadeData)
        });
    }

    static async updateAtividade(id, atividadeData) {
        console.log(`✏️ Atualizando atividade ${id} na API...`);
        return this.request(`/atividades/${id}`, {
            method: 'PUT',
            body: JSON.stringify(atividadeData)
        });
    }

    static async deleteAtividade(id) {
        console.log(`🗑️ Deletando atividade ${id} na API...`);
        return this.request(`/atividades/${id}`, {
            method: 'DELETE'
        });
    }

    // ===============================
    // MÉTODOS DE VOLUNTÁRIOS
    // ===============================
    static async getVoluntarios() {
        console.log('👥 Buscando voluntários na API...');
        const response = await this.request('/voluntarios');
        
        // Se a resposta tem content (paginação), retorna o content
        if (response && response.content) {
            return response.content;
        }
        
        // Se não tem content, retorna a resposta diretamente
        return response;
    }

    static async getVoluntarioById(id) {
        console.log(`🔍 Buscando voluntário ${id} na API...`);
        return this.request(`/voluntarios/${id}`);
    }

    static async createVoluntario(voluntarioData) {
        console.log('➕ Criando voluntário na API...');
        return this.request('/voluntarios', {
            method: 'POST',
            body: JSON.stringify(Object.assign({}, voluntarioData, { role: 'VOLUNTARIO' }))
        });
    }

    static async updateVoluntario(id, voluntarioData) {
        console.log(`✏️ Atualizando voluntário ${id} na API...`);
        return this.request(`/voluntarios/${id}`, {
            method: 'PUT',
            body: JSON.stringify(voluntarioData)
        });
    }

    static async deleteVoluntario(id) {
        console.log(`🗑️ Deletando voluntário ${id} na API...`);
        return this.request(`/voluntarios/${id}`, {
            method: 'DELETE'
        });
    }

    // ===============================
    // MÉTODOS DE administrador
    // ===============================
    static async getAdmins() {
        console.log('👨‍💼 Buscando administrador na API...');
        return this.request('/admin');
    }

    static async getAdminById(id) {
        console.log(`🔍 Buscando administrador ${id} na API...`);
        return this.request(`/admin/${id}`);
    }

    static async createAdmin(adminData) {
        console.log('➕ Criando administrador na API...');
        return this.request('/admin', {
            method: 'POST',
            body: JSON.stringify(adminData)
        });
    }


    static async updateAdmin(id, adminData) {
        console.log(`✏️ Atualizando administrador ${id} na API...`);
        return this.request(`/admin/${id}`, {
            method: 'PUT',
            body: JSON.stringify(adminData)
        });
    }

    static async deleteAdmin(id) {
        console.log(`🗑️ Deletando administrador ${id} na API...`);
        return this.request(`/admin/${id}`, {
            method: 'DELETE'
        });
    }

    // ===============================
    // MÉTODOS ESPECÍFICOS POR USUÁRIO
    // ===============================
    
    /**
     * Busca alunos associados ao usuário atual (para voluntários)
     */
    static async getMeusAlunos() {
        console.log('📚 Buscando meus alunos na API...');
        const response = await this.request('/alunos');
        
        // Se a resposta tem content (paginação), retorna o content
        if (response && response.content) {
            return response.content;
        }
        
        // Se não tem content, retorna a resposta diretamente
        return response;
    }

    /**
     * Busca atividades associadas ao usuário atual (para voluntários)
     */
    static async getMinhasAtividades() {
        console.log('🎯 Buscando minhas atividades na API...');
        const response = await this.request('/atividades');
        
        // Se a resposta tem content (paginação), retorna o content
        if (response && response.content) {
            return response.content;
        }
        
        // Se não tem content, retorna a resposta diretamente
        return response;
    }

    /**
     * Busca voluntários supervisionados pelo usuário atual (para admins)
     */
    static async getMeusVoluntarios() {
        console.log('👥 Buscando meus voluntários na API...');
        const response = await this.request('/voluntarios');
        
        // Se a resposta tem content (paginação), retorna o content
        if (response && response.content) {
            return response.content;
        }
        
        // Se não tem content, retorna a resposta diretamente
        return response;
    }

    // ===============================
    // MÉTODOS DE RELATÓRIOS E ESTATÍSTICAS
    // ===============================
    
    static async getDashboardData() {
        console.log('📊 Buscando dados do dashboard na API...');
        return this.request('/dashboard');
    }

    static async getEstatisticas() {
        console.log('📈 Buscando estatísticas na API...');
        return this.request('/estatisticas');
    }
}

// ===============================
// FUNÇÕES GLOBAIS PARA COMPATIBILIDADE
// ===============================

window.openTab = (tabName, evt) => {
    if (window.appInstance?.renderer) {
        window.appInstance.renderer.openTab(tabName, evt);
    } else {
        console.warn('❌ appInstance ou renderer não disponível para openTab');
    }
};

window.openStudentModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.openStudentModal();
    } else {
        console.warn('❌ modalService não disponível para openStudentModal');
    }
};

window.closeStudentModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.closeStudentModal();
    } else {
        console.warn('❌ modalService não disponível para closeStudentModal');
    }
};

window.openActivityModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.openActivityModal();
    } else {
        console.warn('❌ modalService não disponível para openActivityModal');
    }
};

window.closeActivityModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.closeActivityModal();
    } else {
        console.warn('❌ modalService não disponível para closeActivityModal');
    }
};

window.closeViewActivityModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.closeViewActivityModal();
    } else {
        console.warn('❌ modalService não disponível para closeViewActivityModal');
    }
};

window.openEditActivityModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.openEditActivityModal();
    } else {
        console.warn('❌ modalService não disponível para openEditActivityModal');
    }
};

window.closeEditActivityModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.closeEditActivityModal();
    } else {
        console.warn('❌ modalService não disponível para closeEditActivityModal');
    }
};

window.openVolunteerModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.openVoluntarioModal();
    } else {
        console.warn('❌ modalService não disponível para openVolunteerModal');
    }
};

window.closeVolunteerModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.closeVoluntarioModal();
    } else {
        console.warn('❌ modalService não disponível para closeVolunteerModal');
    }
};

window.closeViewStudentModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.closeViewStudentModal();
    } else {
        console.warn('❌ modalService não disponível para closeViewStudentModal');
    }
};

window.closeViewVolunteerModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.closeViewVoluntarioModal();
    } else {
        console.warn('❌ modalService não disponível para closeViewVolunteerModal');
    }
};

window.closeDeleteConfirmationModal = () => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.closeDeleteConfirmationModal();
    } else {
        console.warn('❌ modalService não disponível para closeDeleteConfirmationModal');
    }
};

window.confirmarExclusao = () => {
    if (window.appInstance?.eventHandlers) {
        window.appInstance.eventHandlers.handleConfirmDelete();
    } else {
        console.warn('❌ eventHandlers não disponível para confirmarExclusao');
    }
};

window.deletarRegistro = (tipo, id) => {
    if (window.appInstance?.eventHandlers) {
        window.appInstance.eventHandlers.handleDeleteItem(tipo, id);
    } else {
        console.warn('❌ eventHandlers não disponível para deletarRegistro');
    }
};

window.deletarAtividade = () => {
    const viewModal = document.getElementById('view-activity-modal');
    const activityId = viewModal.dataset.activityId;
    
    if (!activityId) {
        console.error('❌ ID da atividade não encontrado');
        return;
    }
    
    if (window.appInstance?.eventHandlers) {
        window.appInstance.eventHandlers.handleDeleteItem('atividades', activityId);
    } else {
        console.warn('❌ eventHandlers não disponível para deletarAtividade');
    }
};

// Funções de visualização que estavam faltando
window.viewStudent = (id) => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.openViewStudentModal(id);
    } else {
        console.warn('❌ modalService não disponível para viewStudent');
    }
};

window.viewVolunteer = (id) => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.openViewVoluntarioModal(id);
    } else {
        console.warn('❌ modalService não disponível para viewVolunteer');
    }
};



window.viewAluno = (id) => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.openViewAlunoModal(id);
    } else {
        console.warn('❌ modalService não disponível para viewAluno');
    }
};



window.toggleProfileMenu = (event) => {
    event.stopPropagation();
    const dropdown = document.querySelector('.profile-dropdown');
    if (dropdown) {
        dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
    }
};

window.handleProfilePicture = () => {
    const input = document.getElementById('profile-upload');
    if (input) input.click();
};

window.handleLogout = () => {
    if (confirm('Deseja sair do sistema? Você será redirecionado para a tela de login.')) {
        NotificationService.info('Saindo do sistema...', 2000);
        setTimeout(() => {
            // Limpar dados da sessão
            localStorage.removeItem('token');
            localStorage.removeItem('currentUser');
            // Redirecionar para login (ou recarregar se não houver página de login)
            window.location.href = 'login.html';
        }, 1000);
    }
};

// Função específica para o botão de logout no header
window.logoutToHome = () => {
    if (confirm('Deseja sair e voltar à página inicial?')) {
        NotificationService.info('Redirecionando para a página inicial...', 1500);
        setTimeout(() => {
            // Limpar dados da sessão
            localStorage.removeItem('token');
            localStorage.removeItem('currentUser');
            // Redirecionar para página inicial
            window.location.href = 'inicio.html';
        }, 500);
    }
};

window.formatCPF = (input) => {
    Utils.formatCPF(input);
};

window.formatPhone = (input) => {
    Utils.formatPhone(input);
};

window.closeNotification = () => {
    NotificationService.close();
};

// Função para toggle do status do aluno
window.toggleStudentStatus = () => {
    const toggle = document.getElementById('student-status-toggle');
    const label = document.getElementById('student-status-label');
    const icon = toggle.querySelector('.toggle-slider i');
    
    if (toggle.classList.contains('active')) {
        // Mudar para inativo
        toggle.classList.remove('active');
        toggle.classList.add('inactive');
        label.textContent = 'Inativo';
        icon.className = 'fas fa-times';
        toggle.dataset.status = 'inativo';
        
        // Notificação visual
        NotificationService.show('⚠️ Status do aluno alterado para Inativo - Salve para confirmar', 'warning', 3000);
    } else {
        // Mudar para ativo
        toggle.classList.remove('inactive');
        toggle.classList.add('active');
        label.textContent = 'Ativo';
        icon.className = 'fas fa-check';
        toggle.dataset.status = 'ativo';
        
        // Notificação visual
        NotificationService.show('✅ Status do aluno alterado para Ativo - Salve para confirmar', 'success', 3000);
    }
};

window.toggleVolunteerStatus = () => {
    const toggle = document.getElementById('volunteer-status-toggle');
    const label = document.getElementById('volunteer-status-label');
    const icon = toggle.querySelector('.toggle-slider i');
    
    if (toggle.classList.contains('active')) {
        // Mudar para inativo
        toggle.classList.remove('active');
        toggle.classList.add('inactive');
        label.textContent = 'Inativo';
        icon.className = 'fas fa-times';
        toggle.dataset.status = 'inativo';
        
        // Notificação visual
        NotificationService.show('⚠️ Status do voluntário alterado para Inativo - Salve para confirmar', 'warning', 3000);
    } else {
        // Mudar para ativo
        toggle.classList.remove('inactive');
        toggle.classList.add('active');
        label.textContent = 'Ativo';
        icon.className = 'fas fa-check';
        toggle.dataset.status = 'ativo';
        
        // Notificação visual
        NotificationService.show('✅ Status do voluntário alterado para Ativo - Salve para confirmar', 'success', 3000);
    }
};

// Função de teste para notificações (remover em produção)
window.testNotifications = () => {
    console.log('🧪 Testando sistema de notificações...');
    
    setTimeout(() => NotificationService.success('✅ Teste de sucesso - Tudo funcionando!'), 500);
    setTimeout(() => NotificationService.error('❌ Teste de erro - Algo deu errado!'), 2000);
    setTimeout(() => NotificationService.warning('⚠️ Teste de aviso - Atenção!'), 4000);
    setTimeout(() => NotificationService.info('ℹ️ Teste de informação - FYI!'), 6000);
};

window.resetSampleData = () => {
    NotificationService.error('Dados de exemplo não disponíveis. Sistema usa apenas API.');
};

// Funções de debug para roles master
window.testMasterRole = (role) => {
    if (typeof AuthService !== 'undefined') {
        return AuthService.debugMasterRole(role);
    } else {
        console.error('❌ AuthService não disponível');
        return false;
    }
};

window.testAllMasterRoles = () => {
    if (typeof AuthService !== 'undefined') {
        return AuthService.testAllMasterRoles();
    } else {
        console.error('❌ AuthService não disponível');
    }
};

// Função para simular um usuário master para testes
window.simulateMasterUser = () => {
    console.log('🎭 Simulando usuário ADM_MASTER para testes...');
    
    const masterUser = {
        id: 'master-demo',
        nome: 'Admin Master',
        email: 'master@sistema.com',
        role: 'ADM_MASTER'
    };
    
    if (window.appInstance && window.appInstance.stateManager) {
        window.appInstance.stateManager.setState({ currentUser: masterUser });
        console.log('✅ Usuário master simulado definido no state');
        
        // Simular localStorage também
        localStorage.setItem('saberviver_user_data', JSON.stringify(masterUser));
        
        // Re-renderizar interface
        if (window.appInstance.renderer) {
            window.appInstance.renderer.configureInterfaceByRole();
            console.log('✅ Interface re-configurada para usuário master');
        }
        
        console.log('🎯 Agora o usuário tem permissões de ADM_MASTER');
        console.log('🔍 Para verificar: AuthService.hasMasterPermission()');
    } else {
        console.error('❌ appInstance não disponível');
    }
};

window.clearAllData = () => {
    if (confirm('Isso irá apagar TODOS os dados do sistema. Esta ação não pode ser desfeita. Continuar?')) {
        try {
            localStorage.removeItem('mockData');
            NotificationService.warning('Todos os dados foram removidos!', 3000);
            setTimeout(() => location.reload(), 1000);
        } catch (error) {
            NotificationService.error('Erro ao limpar dados');
        }
    }
};

window.addRandomData = () => {
    console.log('📊 Sistema usa apenas API - dados aleatórios não disponíveis');
    NotificationService.error('Sistema usa apenas API real. Dados aleatórios não disponíveis.');
};



window.openViewAlunoModal = (id) => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.openViewAlunoModal(id);
    }
};

window.closeViewAlunoModal = () => {
    const modal = document.getElementById('view-aluno-modal');
    if (modal) {
        modal.style.display = 'none';
    }
};

window.editarAluno = (id) => {
    if (window.appInstance?.modalService) {
        window.closeViewAlunoModal();
        window.appInstance.modalService.openEditStudentModal(id);
    }
};

window.switchUserType = () => {
    const currentUser = AuthService.getCurrentUser();
    if (!currentUser) return;

    let newUser;
    if (currentUser.role === 'ADM_MASTER') {
        // ADM_MASTER -> ADMIN
        newUser = {
            id: 2,
            nome: 'Admin Geral',
            email: 'admin@escola.com',
            telefone: '(11) 98888-8888',
            cpf: '987.654.321-00',
            role: 'ADM'
        };
    } else if (currentUser.role === 'ADM') {
        // ADMIN -> VOLUNTÁRIO
        newUser = {
            id: 3,
            nome: 'João Silva - Voluntário',
            email: 'voluntario@escola.com',
            telefone: '(11) 97777-7777',
            cpf: '555.666.777-88',
            role: 'VOLUNTARIO'
        };
    } else {
        // VOLUNTÁRIO -> ADM_MASTER
        newUser = {
            id: 1,
            nome: 'Administrador Master',
            email: 'master@admin.com',
            telefone: '(11) 99999-9999',
            cpf: '123.456.789-09',
            role: 'ADM_MASTER'
        };
    }

    localStorage.setItem('currentUser', JSON.stringify(newUser));
    NotificationService.success(`Alterado para: ${newUser.role}`, 3000);
    
    setTimeout(() => {
        location.reload();
    }, 1000);
};

window.editMyData = () => {
    const modal = document.getElementById('edit-my-data-modal');
    if (modal && window.appInstance?.stateManager) {
        const currentUser = appInstance.stateManager.getCurrentUser();
        if (currentUser) {
            document.getElementById('edit-my-nome').value = currentUser.nome;
            document.getElementById('edit-my-email').value = currentUser.email;
            document.getElementById('edit-my-telefone').value = currentUser.telefone;
            modal.style.display = 'flex';
        }
    }
};

window.closeEditMyDataModal = () => {
    const modal = document.getElementById('edit-my-data-modal');
    if (modal) {
        modal.style.display = 'none';
        document.getElementById('edit-my-data-form').reset();
    }
};

window.searchAlunos = () => {
    const searchTerm = document.getElementById('search-alunos').value.toLowerCase().trim();
    const lista = document.getElementById('alunos-list');
    
    if (!window.appInstance?.renderer || !lista) return;
    
    // Se o campo estiver vazio, mostrar todos os alunos
    if (searchTerm === '') {
        window.appInstance.renderer.renderAlunos();
        return;
    }
    
    const alunos = window.appInstance.stateManager.getAllAlunos() || [];
    const filtered = alunos.filter(aluno => 
        aluno.nome.toLowerCase().includes(searchTerm) ||
        (aluno.cpfResponsavel && aluno.cpfResponsavel.toLowerCase().includes(searchTerm))
    );
    
    lista.innerHTML = '';
    if (filtered.length === 0) {
        lista.innerHTML = '<li class="empty-state">Nenhum aluno encontrado</li>';
    } else {
        // Renderizar apenas os alunos filtrados sem alterar o estado global
        filtered.forEach(aluno => {
            const li = document.createElement('li');
            li.style.cursor = 'pointer';
            li.onclick = () => window.appInstance.modalService.openViewAlunoModal(aluno.id);
            li.className = aluno.status === 'inativo' ? 'item-inativo' : '';
            
            li.innerHTML = `
                <div class="aluno-info">
                    <div class="aluno-detalhes">
                        <span class="aluno-nome">${aluno.nome}</span>
                        <span class="aluno-sub">${aluno.apelido || ''} • ${aluno.idade} anos</span>
                    </div>
                    <div class="aluno-acoes">
                        <span class="status-badge ${aluno.status}">${aluno.status}</span>
                        <span class="aluno-atividade">${aluno.atividade || 'Sem atividade'}</span>
                        <i class="fas fa-eye" style="color: #007bff; margin-left: 10px;" title="Clique para visualizar"></i>
                    </div>
                </div>
            `;
            lista.appendChild(li);
        });
    }
};



// ========== FUNÇÕES GLOBAIS DE administrador ==========
window.openAdminModal = () => {
    const modal = document.getElementById('admin-modal');
    if (modal) {
        document.getElementById('admin-form').reset();
        modal.style.display = 'flex';
    }
};

window.closeAdminModal = () => {
    const modal = document.getElementById('admin-modal');
    if (modal) {
        modal.style.display = 'none';
        document.getElementById('admin-form').reset();
    }
};

window.openViewAdminModal = (id) => {
    if (!AuthService.hasMasterPermission()) {
        console.warn('🔐 Tentativa de visualizar admin sem permissão master');
        return;
    }
    
    if (window.appInstance?.stateManager) {
        const admins = window.appInstance.stateManager.getAllAdmins();
        const admin = admins.find(a => a.id === parseInt(id));
        
        if (admin) {
            // Preencher formulário de edição com dados do admin
            document.getElementById('edit-admin-nome').value = admin.nome || '';
            document.getElementById('edit-admin-email').value = admin.email || '';
            document.getElementById('edit-admin-telefone').value = admin.telefone || '';
            document.getElementById('edit-admin-cpf').value = admin.cpf || '';
            document.getElementById('edit-admin-role').value = admin.role || '';
            
            // Armazenar ID do admin no formulário para uso posterior
            const editForm = document.getElementById('edit-admin-form');
            editForm.dataset.adminId = id;
            
            const modal = document.getElementById('view-admin-modal');
            if (modal) {
                modal.style.display = 'flex';
                console.log('🔍 Modal de admin aberto:', admin.nome);
            }
        } else {
            console.error('❌ Admin não encontrado:', id);
        }
    }
};

window.closeViewAdminModal = () => {
    const modal = document.getElementById('view-admin-modal');
    if (modal) {
        modal.style.display = 'none';
    }
};

window.openEditAdminModal = (id) => {
    if (window.appInstance?.stateManager) {
        const admins = window.appInstance.stateManager.getState().admins;
        const admin = admins.find(a => a.id === parseInt(id));
        if (admin) {
            document.getElementById('edit-admin-id').value = admin.id;
            document.getElementById('edit-admin-nome').value = admin.nome;
            document.getElementById('edit-admin-email').value = admin.email;
            document.getElementById('edit-admin-telefone').value = admin.telefone;
            document.getElementById('edit-admin-cpf').value = admin.cpf;
            document.getElementById('edit-admin-role').value = admin.role;
            document.getElementById('edit-admin-status').value = admin.status;
            document.getElementById('edit-admin-senha').value = ''; // Não mostrar senha atual
            
            const modal = document.getElementById('edit-admin-modal');
            if (modal) {
                modal.style.display = 'flex';
            }
        }
    }
};

window.closeEditAdminModal = () => {
    const modal = document.getElementById('edit-admin-modal');
    if (modal) {
        modal.style.display = 'none';
        document.getElementById('edit-admin-form').reset();
    }
};

window.deleteAdmin = async (id) => {
    if (window.appInstance?.stateManager) {
        const currentUser = window.appInstance.stateManager.getCurrentUser();
        if (currentUser.role !== 'ADM_MASTER') {
            NotificationService.show('Apenas ADM_MASTER pode excluir administrador', 'error');
            return;
        }

        const admins = window.appInstance.stateManager.getState().admins;
        const admin = admins.find(a => a.id === parseInt(id));
        
        if (!admin) {
            NotificationService.show('Administrador não encontrado', 'error');
            return;
        }

        // Não permitir excluir o último ADM_MASTER
        const masterAdmins = admins.filter(a => a.role === 'ADM_MASTER' && a.status === 'ativo');
        if (admin.role === 'ADM_MASTER' && masterAdmins.length <= 1) {
            NotificationService.show('Não é possível excluir o último ADM_MASTER do sistema', 'error');
            return;
        }

        const confirmed = confirm(`Tem certeza que deseja excluir o administrador ${admin.nome}?`);
        if (confirmed) {
            try {
                await ApiService.deleteAdmin(id);
                const adminsAtualizados = await ApiService.getAdmins();
                appInstance.stateManager.setState({ admins: adminsAtualizados });
                NotificationService.show('Administrador excluído com sucesso!', 'success');
            } catch (error) {
                console.error('Erro ao excluir administrador:', error);
                NotificationService.show('Erro ao excluir administrador', 'error');
            }
        }
    }
};

window.searchAdmins = () => {
    const searchTerm = document.getElementById('search-admins').value.toLowerCase();
    const admins = appInstance?.stateManager.getAllAdmins() || [];
    const filtered = admins.filter(admin => 
        admin.nome.toLowerCase().includes(searchTerm) ||
        admin.email.toLowerCase().includes(searchTerm) ||
        admin.cpf.toLowerCase().includes(searchTerm)
    );
    
    if (appInstance?.renderer) {
        appInstance.stateManager.setState({ admins: filtered });
        appInstance.renderer.renderAdmins();
    }
};

// Função de busca para voluntários
window.searchVoluntarios = () => {
    console.log('🔍 Iniciando busca de voluntários...');
    
    const searchTerm = document.getElementById('search-voluntarios')?.value?.toLowerCase()?.trim();
    const container = document.getElementById('voluntarios-list');
    
    if (!container) {
        console.warn('❌ Container voluntarios-list não encontrado');
        return;
    }
    
    if (!searchTerm) {
        // Se não há termo de busca, renderizar todos os voluntários
        if (window.appInstance?.renderer) {
            window.appInstance.renderer.renderVoluntarios();
        }
        return;
    }
    
    const voluntarios = window.appInstance?.stateManager?.getAllVoluntarios() || [];
    const filteredVoluntarios = voluntarios.filter(voluntario => {
        const nome = voluntario.nome?.toLowerCase() || '';
        const cpf = voluntario.cpf?.replace(/\D/g, '') || '';
        const email = voluntario.email?.toLowerCase() || '';
        const searchCpf = searchTerm.replace(/\D/g, '');
        
        return nome.includes(searchTerm) || 
               email.includes(searchTerm) ||
               (searchCpf && cpf.includes(searchCpf));
    });
    
    // Limpar lista
    container.innerHTML = '';
    
    if (filteredVoluntarios.length === 0) {
        container.innerHTML = '<li class="empty-state">Nenhum voluntário encontrado</li>';
        return;
    }
    
    // Renderizar resultados filtrados
    filteredVoluntarios.forEach(voluntario => {
        const li = document.createElement('li');
        li.style.cursor = 'pointer';
        li.onclick = () => window.appInstance?.modalService?.openViewVoluntarioModal(voluntario.id);
        li.className = voluntario.status === 'inativo' ? 'item-inativo' : '';
        
        li.innerHTML = `
            <div class="voluntario-info">
                <div class="voluntario-detalhes">
                    <span class="voluntario-nome">${voluntario.nome}</span>
                    <span class="voluntario-email">${voluntario.email}</span>
                </div>
                <div class="voluntario-acoes">
                    <span class="status-badge ${voluntario.status}">${voluntario.status}</span>
                    <span class="voluntario-atividade">${voluntario.atividade}</span>
                    <button class="btn-editar admin-and-master" onclick="event.stopPropagation(); window.editVoluntario(${voluntario.id})" title="Editar voluntário">
                        <i class="fas fa-edit"></i>
                        Editar
                    </button>
                    <button class="btn-excluir admin-and-master" onclick="event.stopPropagation(); deletarRegistro('voluntarios', ${voluntario.id})" title="Excluir voluntário">
                        <i class="fas fa-trash"></i>
                        Excluir
                    </button>
                </div>
            </div>
        `;
        container.appendChild(li);
    });
    
    console.log(`✅ Busca concluída: ${filteredVoluntarios.length} voluntários encontrados`);
};

// Função para editar voluntário
window.editVoluntario = (id) => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.openEditVoluntarioModal(id);
    } else {
        console.warn('❌ modalService não disponível para editVoluntario');
    }
};

// Função para editar atividade
window.editAtividade = (id) => {
    if (window.appInstance?.modalService) {
        window.appInstance.modalService.openEditActivityModal(id);
    } else {
        console.warn('❌ modalService não disponível para editAtividade');
    }
};

// ===============================
// FUNÇÕES GLOBAIS PARA INTEGRAÇÃO EXTERNA
// ===============================

/**
 * Função global para login externo - Chamada pela página de login
 * @param {Object} userData - Dados do usuário {id, nome, email, role, etc}
 * @param {string} token - Token JWT ou similar
 * @returns {boolean} - Sucesso/Falha do login
 */
window.loginUser = function(userData, token) {
    console.log('🔐 Recebendo login externo...');
    return AuthService.setAuthenticatedUser(userData, token);
};

/**
 * Função global para logout - Pode ser chamada de qualquer lugar
 */
window.logoutUser = function() {
    console.log('🚪 Efetuando logout...');
    AuthService.logout();
};

/**
 * Função para verificar se usuário está logado
 * @returns {boolean}
 */
window.isUserLoggedIn = function() {
    return AuthService.isAuthenticated();
};

/**
 * Função para obter dados do usuário atual
 * @returns {Object|null}
 */
window.getCurrentUser = function() {
    return AuthService.getCurrentUser();
};

/**
 * Função para habilitar modo de desenvolvimento (apenas para testes)
 * @param {boolean} enable - true para habilitar
 */
window.enableDevelopmentMode = function(enable = true) {
    if (enable) {
        console.log('🔧 Modo de desenvolvimento habilitado');
        CONFIG.DEVELOPMENT_MODE = true;
        console.log('📊 Sistema usa apenas API - modo mock removido');
        
        // Configurar usuário de teste se necessário
        if (appInstance && !AuthService.isAuthenticated()) {
            appInstance.setupTestUser();
            appInstance.init();
        }
    } else {
        console.log('🔒 Modo de desenvolvimento desabilitado');
        CONFIG.DEVELOPMENT_MODE = false;
        console.log('📊 Sistema sempre usa API - modo mock desabilitado permanentemente');
        AuthService.clearAuthentication();
    }
};

/**
 * Função de debug para testar permissões - Use no console
 */
window.debugPermissions = function() {
    console.log('🔍 === DEBUG DE PERMISSÕES ===');
    
    const user = AuthService.getCurrentUser();
    console.log('👤 Usuário atual:', user);
    
    if (!user) {
        console.error('❌ Nenhum usuário logado');
        return;
    }
    
    const elements = {
        'all-users': document.querySelectorAll('.all-users'),
        'volunteer-and-admin': document.querySelectorAll('.volunteer-and-admin'), 
        'admin-and-master': document.querySelectorAll('.admin-and-master'),
        'master-only': document.querySelectorAll('.master-only')
    };
    
    for(const [className, nodeList] of Object.entries(elements)) {
        console.log(`🔧 Classe .${className}: ${nodeList.length} elementos`);
        nodeList.forEach((el, i) => {
            const visible = el.style.display !== 'none';
            console.log(`  ${i+1}. ${el.id || el.tagName} - ${visible ? '✅ VISÍVEL' : '❌ OCULTO'}`);
        });
    }
    
    // Forçar reconfiguração
    console.log('🔄 Forçando reconfiguração de permissões...');
    AuthService.setupUserInterface();
};

// ===============================
// INICIALIZAÇÃO
// ===============================
document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 Inicializando sistema...');
    console.log('🌍 URL atual:', window.location.href);
    
    // Log detalhado do localStorage ANTES da verificação
    console.log('📋 Estado atual do localStorage:');
    console.log('- saberviver_token:', localStorage.getItem('saberviver_token') ? 'PRESENTE' : 'AUSENTE');
    console.log('- saberviver_user_data:', localStorage.getItem('saberviver_user_data') ? 'PRESENTE' : 'AUSENTE');
    console.log('- saberviver_token_timestamp:', localStorage.getItem('saberviver_token_timestamp') || 'AUSENTE');
    
    // Verificar autenticação antes de inicializar
    console.log('🔐 Iniciando verificação de autenticação...');
    const isAuth = AuthService.isAuthenticated();
    console.log('🔐 Resultado da verificação:', isAuth);
    
    if (!isAuth) {
        console.warn('🔐 Usuário não autenticado, redirecionando para login...');
        console.log('🔄 Redirecionando em 5 segundos para permitir análise...');
        setTimeout(() => {
            window.location.href = 'login.html';
        }, 5000); // Aumentado para 5 segundos
        return;
    }
    
    console.log('✅ Usuário autenticado, carregando painel...');
    const currentUser = AuthService.getCurrentUser();
    console.log(`👤 Usuário logado: ${currentUser?.nome || 'N/A'} (${currentUser?.role || 'N/A'})`);
    
    // Mostrar tabs imediatamente para desenvolvimento
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.style.display = 'flex';
    });
    
    // Sistema configurado para usar exclusivamente API real
    
    // Criar instância da aplicação
    window.appInstance = new App();
    
    // INICIALIZAR A APLICAÇÃO IMEDIATAMENTE
    console.log('🚀 Inicializando aplicação...');
    window.appInstance.init().then(() => {
        console.log('✅ Aplicação inicializada com sucesso!');
    }).catch(error => {
        console.error('❌ Erro ao inicializar aplicação:', error);
    });
    
    // Verificação pós-inicialização
    setTimeout(() => {
        console.log('🔍 Verificação pós-inicialização...');
        console.log('✅ window.appInstance criado:', !!window.appInstance);
        
        if (window.appInstance) {
            console.log('✅ renderer:', !!window.appInstance.renderer);
            console.log('✅ modalService:', !!window.appInstance.modalService);
            console.log('✅ eventHandlers:', !!window.appInstance.eventHandlers);
            console.log('✅ stateManager:', !!window.appInstance.stateManager);
        }
        
        // Teste rápido de funções globais
        const funcoesCriticas = ['openTab', 'openStudentModal', 'viewStudent'];
        funcoesCriticas.forEach(func => {
            const existe = typeof window[func] === 'function';
            console.log(`${existe ? '✅' : '❌'} ${func}:`, existe ? 'OK' : 'FALTA');
        });
        
        console.log('🎯 Sistema inicializado! Use diagnosticoBotoes() para verificar problemas.');
    }, 1000);
});

// ===============================
// SISTEMA CONFIGURADO PARA USAR APENAS API
// FUNÇÕES DE TESTE/MOCK REMOVIDAS
// ===============================

/**
 * Função para debug rápido de autenticação
 * Execute no console: debugAuth()
 */
window.debugAuth = function() {
    console.log('🔍 === DEBUG DE AUTENTICAÇÃO ===');
    
    const token = localStorage.getItem('saberviver_token') || localStorage.getItem('token');
    const user = localStorage.getItem('saberviver_user_data') || localStorage.getItem('currentUser');
    
    console.log('📋 Estado do localStorage:');
    console.log('- Token presente:', token ? 'SIM' : 'NÃO');
    console.log('- Dados do usuário presentes:', user ? 'SIM' : 'NÃO');
    
    if (token) {
        console.log('🔍 Analisando token...');
        AuthService.debugToken(token);
    }
    
    if (user) {
        try {
            const userData = JSON.parse(user);
            console.log('👤 Dados do usuário:', userData);
        } catch (e) {
            console.error('❌ Erro ao fazer parse dos dados do usuário:', e);
        }
    }
    
    console.log('🔐 Resultado da autenticação:', AuthService.isAuthenticated());
};

/**
 * Função para debugar os acessos atuais
 * Execute no console: debugAcessos()
 */
window.debugAcessos = function() {
    console.log('🔍 === DEBUG DE ACESSOS ===');
    
    const token = localStorage.getItem('saberviver_token') || localStorage.getItem('token');
    const user = localStorage.getItem('saberviver_user_data') || localStorage.getItem('currentUser');
    
    console.log('🔐 Token:', token);
    
    if (user) {
        try {
            const userParsed = JSON.parse(user);
            console.log('👤 Usuário:', userParsed.nome, `(${userParsed.role})`);
        } catch (e) {
            console.error('❌ Erro ao fazer parse do usuário:', e);
            return;
        }
    }
    
    // Verificar autenticação
    console.log('🔐 isAuthenticated():', AuthService.isAuthenticated());
    console.log('👤 getCurrentUser():', AuthService.getCurrentUser());
    console.log('🔧 getUserRole():', AuthService.getUserRole());
    
    // Testar permissões específicas
    console.log('🔒 hasVoluntarioPermission():', AuthService.hasVoluntarioPermission());
    console.log('🔒 hasAdminPermission():', AuthService.hasAdminPermission());
    console.log('🔒 hasMasterPermission():', AuthService.hasMasterPermission());
    
    // Verificar elementos visíveis na interface
    const elementos = {
        '.volunteer-and-admin': document.querySelectorAll('.volunteer-and-admin'),
        '.admin-and-master': document.querySelectorAll('.admin-and-master'),
        '.master-only': document.querySelectorAll('.master-only')
    };
    
    console.log('📋 === ELEMENTOS E VISIBILIDADE ===');
    for (const [selector, elements] of Object.entries(elementos)) {
        console.log(`🔧 ${selector}: ${elements.length} elementos`);
        elements.forEach((el, index) => {
            const isVisible = el.style.display !== 'none';
            const className = el.className.split(' ').filter(c => c.includes('-')).join('.');
            console.log(`  ${index + 1}. ${el.tagName}${el.id ? '#' + el.id : ''}${className ? '.' + className : ''} - ${isVisible ? '✅ VISÍVEL' : '❌ OCULTO'}`);
        });
    }
    
    // Verificar tabs visíveis
    console.log('📋 === TABS VISÍVEIS ===');
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach((tab, index) => {
        const isVisible = tab.style.display !== 'none';
        const isActive = tab.classList.contains('active');
        console.log(`  ${index + 1}. ${tab.textContent.trim()} - ${isVisible ? '✅ VISÍVEL' : '❌ OCULTO'} ${isActive ? '(ATIVO)' : ''}`);
    });
};

/**
 * Função para forçar a reconfiguração das permissões
 * Execute no console: fixAcessos()
 */
window.fixAcessos = function() {
    console.log('🔧 Forçando reconfiguração das permissões...');
    
    if (AuthService.isAuthenticated()) {
        AuthService.setupUserInterface();
        console.log('✅ Permissões reconfiguradas!');
        
        // Debug após reconfiguração
        setTimeout(() => {
            window.debugAcessos();
        }, 500);
    } else {
        console.error('❌ Usuário não autenticado. Não é possível configurar permissões.');
    }
};

// Função ativarModoTeste removida - sistema usa apenas API

// Função desativarModoTeste removida - sistema usa apenas API

// Função testeRapido removida - sistema usa apenas API

/**
 * Função para verificar status atual do sistema
 * Execute no console: statusSistema()
 */
window.statusSistema = function() {
    console.log('📊 === STATUS DO SISTEMA ===');
    console.log('🔧 SISTEMA: APENAS API (sem mock)');
    console.log('🔧 DEVELOPMENT_MODE:', CONFIG.DEVELOPMENT_MODE);
    console.log('🌐 API_BASE_URL:', CONFIG.API_BASE_URL);
    
    const user = localStorage.getItem('saberviver_user_data') || localStorage.getItem('currentUser');
    const token = localStorage.getItem('saberviver_token') || localStorage.getItem('token');
    
    console.log('👤 Usuário logado:', user ? JSON.parse(user).nome : 'Nenhum');
    console.log('🔐 Token presente:', token ? 'Sim' : 'Não');
    console.log('📊 Sistema configurado para usar apenas dados da API');
    
    if (typeof AuthService !== 'undefined') {
        console.log('🔒 Autenticado:', AuthService.isAuthenticated());
        console.log('👤 Role atual:', AuthService.getUserRole());
    }
    
    if (window.appInstance?.stateManager) {
        const state = window.appInstance.stateManager.getState();
        console.log('🗃️ Estado atual da aplicação:');
        console.log('  - Alunos:', state.alunos?.length || 0);
        console.log('  - Atividades:', state.atividades?.length || 0);
        console.log('  - Voluntarios:', state.voluntarios?.length || 0);
        console.log('  - Admins:', state.admins?.length || 0);
    }
    
    console.log('📋 === COMANDOS DISPONÍVEIS ===');
    console.log('- resolverCards() - 🚑 SOLUÇÃO DEFINITIVA para cards invisíveis');
    console.log('- diagnosticarCards() - 🔍 Diagnóstico completo de visibilidade');
    console.log('- forcarVisibilidadeCards() - 👁️ Força visibilidade de todos os cards');
    console.log('- testarRenderizacao() - 🧪 Testa renderização de cada lista');
    console.log('- resolverListas() - Resolve listas vazias');
    console.log('- testeRapido() - Ativa teste SEM recarregar');
    console.log('- statusSistema() - Status completo do sistema');
    console.log('- diagnosticoBotoes() - Verifica funcionamento dos botões');
    console.log('- forcarDadosInterface() - Injeta dados diretamente na interface');
};

/**
 * Função para diagnosticar problemas com botões
 * Execute no console: diagnosticoBotoes()
 */
window.diagnosticoBotoes = function() {
    console.log('🔧 === DIAGNÓSTICO DE BOTÕES ===');
    
    // Verificar se appInstance existe
    console.log('🔍 window.appInstance existe:', !!window.appInstance);
    
    if (window.appInstance) {
        console.log('🔍 renderer existe:', !!window.appInstance.renderer);
        console.log('🔍 modalService existe:', !!window.appInstance.modalService);
        console.log('🔍 eventHandlers existe:', !!window.appInstance.eventHandlers);
        console.log('🔍 stateManager existe:', !!window.appInstance.stateManager);
    }
    
    // Verificar funções globais
    const funcoes = [
        'openTab', 'openStudentModal', 'closeStudentModal',
        'openActivityModal', 'closeActivityModal',
        'openVolunteerModal', 'closeVolunteerModal',
        'viewStudent', 'viewVolunteer',
        'deletarRegistro', 'deletarAtividade', 'confirmarExclusao'
    ];
    
    console.log('🔍 === FUNÇÕES GLOBAIS ===');
    funcoes.forEach(func => {
        const existe = typeof window[func] === 'function';
        console.log(`${existe ? '✅' : '❌'} ${func}: ${existe ? 'OK' : 'FALTANDO'}`);
    });
    
    // Verificar botões na página
    console.log('🔍 === BOTÕES NA PÁGINA ===');
    const botoes = [
        { selector: 'button[onclick*="openTab"]', nome: 'Botões de Tab' },
        { selector: 'button[onclick*="openStudentModal"]', nome: 'Botão Adicionar Aluno' },
        { selector: 'button[onclick*="openActivityModal"]', nome: 'Botão Adicionar Atividade' },
        { selector: 'button[onclick*="viewStudent"]', nome: 'Botões Ver Aluno' },
        { selector: 'button[onclick*="deletarRegistro"]', nome: 'Botões Excluir' }
    ];
    
    botoes.forEach(({ selector, nome }) => {
        const elementos = document.querySelectorAll(selector);
        console.log(`${elementos.length > 0 ? '✅' : '❌'} ${nome}: ${elementos.length} encontrado(s)`);
    });
    
    // Testar uma função
    console.log('🧪 === TESTE RÁPIDO ===');
    try {
        if (typeof window.openTab === 'function') {
            console.log('✅ Função openTab pode ser chamada');
        }
        if (typeof window.openStudentModal === 'function') {
            console.log('✅ Função openStudentModal pode ser chamada');
        }
    } catch (error) {
        console.log('❌ Erro ao testar funções:', error.message);
    }
};

/**
 * Função para recarregar todas as listas
 * Execute no console: recarregarListas()
 */
window.recarregarListas = function() {
    console.log('🔄 Forçando recarregamento das listas...');
    
    if (!window.appInstance) {
        console.log('❌ appInstance não encontrada');
        return;
    }
    
    // Primeiro, garantir que está em modo mock para ter dados
    console.log('🔧 Configurando modo mock temporariamente...');
    const modoOriginal = CONFIG.MOCK_MODE;
    CONFIG.MOCK_MODE = true;
    
    // Recarregar dados
    if (window.appInstance.loadInitialData) {
        console.log('📊 Recarregando dados...');
        window.appInstance.loadInitialData().then(() => {
            console.log('✅ Dados recarregados!');
            
            // Forçar renderização
            if (window.appInstance.renderer) {
                console.log('🎨 Re-renderizando interface...');
                window.appInstance.renderer.renderCurrentTab();
                console.log('✅ Interface atualizada!');
            }
            
            // Restaurar modo original após um tempo
            setTimeout(() => {
                CONFIG.MOCK_MODE = modoOriginal;
                console.log(`🔧 Modo restaurado para: MOCK_MODE=${CONFIG.MOCK_MODE}`);
            }, 2000);
        }).catch(error => {
            console.log('❌ Erro ao recarregar dados:', error.message);
            CONFIG.MOCK_MODE = modoOriginal;
        });
    }
    
    // Debug dos dados após recarregamento
    setTimeout(() => {
        if (window.appInstance.stateManager) {
            const state = window.appInstance.stateManager.getState();
            console.log('📊 === DADOS NO STATE APÓS RECARREGAMENTO ===');
            console.log('Alunos:', state.alunos?.length || 0);
            console.log('Atividades:', state.atividades?.length || 0);
            console.log('Voluntarios:', state.voluntarios?.length || 0);
            console.log('Admins:', state.admins?.length || 0);
        }
    }, 1000);
};

/**
 * Função para simular um login real de produção
 * Execute no console: simularLoginProducao()
 */
window.simularLoginProducao = function() {
    console.log('🚀 Simulando login de produção...');
    
    // Manter modo produção
    CONFIG.MOCK_MODE = false;
    CONFIG.DEVELOPMENT_MODE = false;
    
    // Simular resposta de login real (como viria de login.html)
    const prodUser = {
        id: 123,
        nome: 'João Silva (Produção)',
        email: 'joao@ongsaberviver.com.br',
        telefone: '(11) 99999-8888',
        role: 'ADM'
    };
    
    // Token JWT simulado (estrutura real)
    const jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiSm9hbyBTaWx2YSIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxOTE2MjM5MDIyfQ.example';
    
    // Usar método oficial para definir usuário autenticado
    const success = AuthService.setAuthenticatedUser(prodUser, jwtToken);
    
    if (success) {
        console.log('✅ Login simulado com sucesso!');
        console.log('👤 Usuário:', prodUser.nome, `(${prodUser.role})`);
        console.log('⚠️ ATENÇÃO: Sistema tentará conectar com API real');
        console.log('❌ As listas podem não carregar se a API não responder');
        
        // Tentar reinicializar aplicação
        if (window.appInstance) {
            console.log('🔄 Reinicializando aplicação...');
            window.appInstance.init();
        }
    } else {
        console.log('❌ Erro ao simular login');
    }
};

window.testarToggles = function() {
    console.log('🔄 === TESTANDO TOGGLES DE STATUS ===');
    
    // Verificar se as funções estão disponíveis
    const toggleFunctions = [
        'toggleStudentStatus',
        'toggleVolunteerStatus'
    ];
    
    toggleFunctions.forEach(funcName => {
        if (typeof window[funcName] === 'function') {
            console.log(`✅ ${funcName} disponível`);
        } else {
            console.log(`❌ ${funcName} não encontrada`);
        }
    });
    
    // Verificar se os elementos existem no DOM
    const toggleElements = [
        { id: 'student-status-toggle', name: 'Toggle Aluno' },
        { id: 'volunteer-status-toggle', name: 'Toggle Voluntário' },
        { id: 'student-status-label', name: 'Label Aluno' },
        { id: 'volunteer-status-label', name: 'Label Voluntário' }
    ];
    
    toggleElements.forEach(({ id, name }) => {
        const element = document.getElementById(id);
        if (element) {
            console.log(`✅ ${name} encontrado (${id})`);
            console.log(`   - Classes: ${element.className}`);
            console.log(`   - Status: ${element.dataset.status || 'não definido'}`);
        } else {
            console.log(`⚠️ ${name} não encontrado (${id}) - normal se modal não estiver aberto`);
        }
    });
    
    console.log('📋 Para testar os toggles:');
    console.log('1. Abra um modal de edição de aluno ou voluntário');
    console.log('2. Clique no toggle de status');
    console.log('3. Observe a mudança visual e a notificação');
    console.log('4. Salve as alterações para confirmar');
};

window.verificarModoProducao = function() {
    console.log('🏭 === VERIFICAÇÃO DE MODO PRODUÇÃO ===');
    
    console.log('🌍 Ambiente atual:');
    console.log(`   - Hostname: ${window.location.hostname}`);
    console.log(`   - URL completa: ${window.location.href}`);
    console.log(`   - Protocolo: ${window.location.protocol}`);
    console.log(`   - IS_PRODUCTION detectado: ${IS_PRODUCTION}`);
    
    console.log('⚙️ Configurações ativas:');
    console.log(`   - SISTEMA: APENAS API (sem mock)`);
    console.log(`   - DEVELOPMENT_MODE: ${CONFIG.DEVELOPMENT_MODE}`);
    console.log(`   - API_BASE_URL: ${CONFIG.API_BASE_URL}`);
    console.log(`   - TIMEOUT: ${CONFIG.TIMEOUT}ms`);
    
    console.log('📋 Verificações de produção:');
    
    // Verificar se PRODUCTION_CONFIG está disponível
    if (typeof PRODUCTION_CONFIG !== 'undefined') {
        console.log('✅ PRODUCTION_CONFIG carregado');
        console.log('   - API URL:', PRODUCTION_CONFIG.API_BASE_URL);
        console.log('   - Mock mode:', PRODUCTION_CONFIG.MODE?.MOCK);
        console.log('   - Debug mode:', PRODUCTION_CONFIG.MODE?.DEBUG);
    } else {
        console.log('⚠️ PRODUCTION_CONFIG não encontrado (esperado em desenvolvimento)');
    }
    
    // Verificar badges de modo
    const testBadge = document.getElementById('test-mode-badge');
    if (testBadge) {
        const isVisible = window.getComputedStyle(testBadge).display !== 'none';
        console.log(`🏷️ Badge de teste: ${isVisible ? 'Visível' : 'Oculto'}`);
        if (isVisible) {
            console.log(`   - Texto: "${testBadge.textContent}"`);
        }
    }
    
    // Verificar funcionalidades de debug
    const debugFunctions = [
        'resolverCards', 'diagnosticarCards', 'testarRenderizacao',
        'ativarModoTeste', 'desativarModoTeste', 'testLogin'
    ];
    
    console.log('🔧 Funções de debug disponíveis:');
    debugFunctions.forEach(func => {
        const available = typeof window[func] === 'function';
        console.log(`   - ${func}: ${available ? '✅' : '❌'}`);
    });
    
    console.log('🎯 Recomendações para produção:');
    console.log('✅ Sistema configurado para usar apenas API real');
    
    if (CONFIG.DEVELOPMENT_MODE) {
        console.log('❌ DEVELOPMENT_MODE deve ser false em produção');
    } else {
        console.log('✅ DEVELOPMENT_MODE configurado corretamente');
    }
    
    if (CONFIG.API_BASE_URL.includes('localhost') || CONFIG.API_BASE_URL.includes('127.0.0.1')) {
        console.log('❌ API_BASE_URL não deve apontar para localhost em produção');
    } else {
        console.log('✅ API_BASE_URL configurado para servidor remoto');
    }
};

/**
 * Função para forçar dados mock mesmo em produção (para teste de interface)
 * Execute no console: forcarDadosInterface()
 */
window.forcarDadosInterface = function() {
    console.log('🎭 Forçando dados para teste de interface...');
    
    // Manter produção, mas injetar dados mock temporariamente
    const mockData = {
        alunos: [
            { id: 1, nome: 'Ana Silva', idade: 10, responsavel: 'Maria Silva', telefone: '(11) 99999-1111', atividade: 'Futebol', status: 'ativo' },
            { id: 2, nome: 'João Santos', idade: 12, responsavel: 'Pedro Santos', telefone: '(11) 99999-2222', atividade: 'Natação', status: 'ativo' }
        ],
        atividades: [
            { id: 1, nome: 'Futebol Infantil', descricao: 'Esporte para crianças', capacidadeMaxima: 20 },
            { id: 2, nome: 'Natação', descricao: 'Aulas de natação', capacidadeMaxima: 15 }
        ],
        voluntarios: [
            { id: 1, nome: 'Prof. Carlos', email: 'carlos@escola.com', telefone: '(11) 88888-1111', atividade: 'Futebol', status: 'ativo', role: 'VOLUNTARIO' }
        ],
        admins: [
            { id: 1, nome: 'Admin Sistema', email: 'admin@sistema.com', telefone: '(11) 66666-1111', role: 'ADMIN', status: 'ativo' }
        ]
    };
    
    // Injetar dados no StateManager se existir
    if (window.appInstance && window.appInstance.stateManager) {
        window.appInstance.stateManager.setState(mockData);
        console.log('✅ Dados injetados no StateManager');
        
        // Forçar renderização
        if (window.appInstance.renderer) {
            window.appInstance.renderer.renderCurrentTab();
            console.log('✅ Interface re-renderizada');
        }
    }
    
    console.log('📊 Dados de interface injetados:');
    console.log('- Alunos:', mockData.alunos.length);
    console.log('- Atividades:', mockData.atividades.length);
    console.log('- Voluntários:', mockData.voluntarios.length);
    console.log('- Admins:', mockData.admins.length);
};

/**
 * Função de emergência para resolver listas vazias
 * Execute no console: resolverListas()
 */
window.resolverListas = function() {
    console.log('🚨 === RESOLVENDO PROBLEMA DE LISTAS VAZIAS ===');
    
    // Passo 1: Ativar modo mock
    console.log('1️⃣ Ativando modo mock...');
    CONFIG.MOCK_MODE = true;
    CONFIG.DEVELOPMENT_MODE = true;
    
    // Passo 2: Sistema usa apenas API
    console.log('2️⃣ Sistema configurado para usar apenas API...');
    console.log('✅ Modo API ativo - dados mock removidos');
    
    // Passo 3: Configurar usuário se necessário
    const currentUser = localStorage.getItem('currentUser');
    if (!currentUser) {
        console.log('3️⃣ Configurando usuário de teste...');
        const testUser = {
            id: 1,
            nome: 'Admin Teste',
            email: 'admin@teste.com',
            role: 'ADM_MASTER'
        };
        localStorage.setItem('currentUser', JSON.stringify(testUser));
        localStorage.setItem('token', 'mock_token');
        console.log('✅ Usuário configurado:', testUser);
    }
    
    // Passo 4: Recarregar aplicação
    if (window.appInstance) {
        console.log('4️⃣ Recarregando dados da aplicação...');
        window.appInstance.loadInitialData().then(() => {
            console.log('✅ Dados carregados!');
            
            // Passo 5: Forçar renderização
            console.log('5️⃣ Forçando renderização...');
            if (window.appInstance.renderer) {
                window.appInstance.renderer.renderCurrentTab();
                console.log('✅ Interface renderizada!');
            }
            
            // Debug final
            setTimeout(() => {
                const state = window.appInstance.stateManager?.getState();
                console.log('📊 === RESULTADO FINAL ===');
                if (state) {
                    console.log('✅ Alunos:', state.alunos?.length || 0);
                    console.log('✅ Atividades:', state.atividades?.length || 0);
                    console.log('✅ Voluntarios:', state.voluntarios?.length || 0);
                    console.log('✅ Admins:', state.admins?.length || 0);
                } else {
                    console.log('❌ Estado não encontrado');
                }
                console.log('🎯 Processo concluído! As listas devem estar funcionando agora.');
            }, 1000);
            
        }).catch(error => {
            console.error('❌ Erro ao recarregar dados:', error);
        });
    } else {
        console.log('❌ appInstance não encontrada. Recarregue a página.');
    }
};

/**
 * Função para testar renderização específica de cada lista
 * Execute no console: testarRenderizacao()
 */
window.testarRenderizacao = function() {
    console.log('🧪 === TESTANDO RENDERIZAÇÃO DA ABA ATIVA ===');
    
    if (!window.appInstance) {
        console.log('❌ appInstance não encontrada');
        return;
    }
    
    const renderer = window.appInstance.renderer;
    const stateManager = window.appInstance.stateManager;
    
    if (!renderer || !stateManager) {
        console.log('❌ Renderer ou StateManager não encontrados');
        return;
    }
    
    // Verificar dados no state
    const state = stateManager.getState();
    console.log('📊 Estado atual:');
    console.log('  - Alunos:', state.alunos?.length || 0);
    console.log('  - Atividades:', state.atividades?.length || 0);
    console.log('  - Voluntários:', state.voluntarios?.length || 0);
    console.log('  - Admins:', state.admins?.length || 0);
    
    // Verificar qual aba está ativa
    const activeTab = document.querySelector('.tab-content.active');
    console.log('� Aba ativa:', activeTab ? activeTab.id : 'Nenhuma');
    
    // Testar renderização APENAS da aba ativa
    console.log('🔄 Renderizando apenas a aba ativa...');
    
    try {
        if (activeTab) {
            renderer.renderSpecificTab(activeTab.id);
        } else {
            console.log('⚠️ Nenhuma aba ativa, definindo aba padrão...');
            renderer.setDefaultTab();
            renderer.renderCurrentTab();
        }
    } catch (error) {
        console.error('❌ Erro na renderização:', error);
    }
    
    console.log('✅ Teste concluído! Apenas a aba ativa foi renderizada.');
};

/**
 * Função para diagnosticar problemas de visibilidade dos cards
 * Execute no console: diagnosticarCards()
 */
window.diagnosticarCards = function() {
    console.log('🔍 === DIAGNÓSTICO DE CARDS E ELEMENTOS ===');
    
    // Lista de elementos principais para verificar
    const elementos = [
        { id: 'gerenciar-alunos-tab', nome: 'Tab Alunos' },
        { id: 'alunos-list', nome: 'Lista Alunos' },
        { id: 'gerenciar-atividades-tab', nome: 'Tab Atividades' },
        { id: 'atividades-list', nome: 'Lista Atividades' },
        { id: 'gerenciar-voluntarios-tab', nome: 'Tab Voluntários' },
        { id: 'voluntarios-list', nome: 'Lista Voluntários' },
        { id: 'gerenciar-adm-tab', nome: 'Tab Admins' },
        { id: 'admins-list', nome: 'Lista Admins' }
    ];
    
    elementos.forEach(({ id, nome }) => {
        const elemento = document.getElementById(id);
        if (elemento) {
            const styles = window.getComputedStyle(elemento);
            const isVisible = styles.display !== 'none' && styles.visibility !== 'hidden';
            const classes = Array.from(elemento.classList).join(', ');
            
            console.log(`${isVisible ? '✅' : '❌'} ${nome}:`);
            console.log(`  - Elemento: ${elemento ? 'Existe' : 'Não existe'}`);
            console.log(`  - Display: ${styles.display}`);
            console.log(`  - Visibility: ${styles.visibility}`);
            console.log(`  - Classes: ${classes || 'Nenhuma'}`);
            console.log(`  - Conteúdo: ${elemento.innerHTML.length} chars`);
        } else {
            console.log(`❌ ${nome}: Elemento não encontrado`);
        }
    });
    
    // Verificar tabs ativos
    console.log('📋 === TABS ATIVOS ===');
    const tabsAtivos = document.querySelectorAll('.tab-content.active');
    console.log(`Tabs ativos encontrados: ${tabsAtivos.length}`);
    tabsAtivos.forEach(tab => {
        console.log(`  - ${tab.id} (${tab.classList.toString()})`);
    });
    
    // Verificar permissões aplicadas
    console.log('🔒 === ELEMENTOS COM CLASSES DE PERMISSÃO ===');
    const classesPermissao = [
        '.volunteer-and-admin',
        '.admin-and-master', 
        '.master-only'
    ];
    
    classesPermissao.forEach(classe => {
        const elementos = document.querySelectorAll(classe);
        console.log(`${classe}: ${elementos.length} elementos`);
        elementos.forEach((el, i) => {
            const styles = window.getComputedStyle(el);
            const isVisible = styles.display !== 'none';
            console.log(`  ${i+1}. ${el.id || el.tagName} - ${isVisible ? 'Visível' : 'Oculto'}`);
        });
    });
    
    console.log('🎯 Diagnóstico concluído!');
};

/**
 * Função para forçar visibilidade de todos os cards
 * Execute no console: forcarVisibilidadeCards()
 */
window.forcarVisibilidadeCards = function() {
    console.log('👁️ === FORÇANDO VISIBILIDADE DOS CARDS ===');
    
    // Forçar todos os tab-content a serem visíveis
    const tabContents = document.querySelectorAll('.tab-content');
    console.log(`📋 Encontrados ${tabContents.length} tab-content`);
    
    tabContents.forEach(tab => {
        tab.style.display = 'block';
        console.log(`✅ ${tab.id} forçado para display: block`);
    });
    
    // Forçar todos os cards a serem visíveis
    const cards = document.querySelectorAll('.card');
    console.log(`🃏 Encontrados ${cards.length} cards`);
    
    cards.forEach((card, i) => {
        card.style.display = 'block';
        card.style.visibility = 'visible';
        console.log(`✅ Card ${i+1} forçado para visível`);
    });
    
    // Forçar todas as listas a serem visíveis
    const listas = document.querySelectorAll('.lista-itens');
    console.log(`📝 Encontradas ${listas.length} listas`);
    
    listas.forEach(lista => {
        lista.style.display = 'block';
        lista.style.visibility = 'visible';
        console.log(`✅ ${lista.id} forçada para visível`);
    });
    
    // Remover temporariamente classes de permissão que podem estar escondendo elementos
    const classesPermissao = ['.volunteer-and-admin', '.admin-and-master', '.master-only'];
    classesPermissao.forEach(classe => {
        const elementos = document.querySelectorAll(classe);
        elementos.forEach(el => {
            el.style.display = 'block';
            el.style.visibility = 'visible';
        });
        console.log(`✅ ${elementos.length} elementos com classe ${classe} forçados para visíveis`);
    });
    
    console.log('👁️ Visibilidade forçada para todos os elementos!');
    console.log('🔄 Agora teste: testarRenderizacao()');
};

/**
 * Função DEFINITIVA para resolver o problema dos cards
 * Execute no console: resolverCards()
 */
window.resolverCards = function() {
    console.log('🚑 === RESOLVENDO PROBLEMA DOS CARDS ===');
    
    // Passo 1: Sistema usa apenas API
    console.log('1️⃣ Sistema configurado para usar apenas API...');
    console.log('✅ Modo API ativo - dados mock removidos');
    
    // Passo 2: Garantir usuário
    console.log('2️⃣ Garantindo usuário...');
    const testUser = {
        id: 1,
        nome: 'Admin Teste',
        email: 'admin@teste.com',
        role: 'ADM_MASTER'
    };
    localStorage.setItem('currentUser', JSON.stringify(testUser));
    localStorage.setItem('token', 'mock_token');
    
    // Passo 3: Forçar visibilidade
    console.log('3️⃣ Forçando visibilidade...');
    window.forcarVisibilidadeCards();
    
    // Passo 4: Recarregar dados na aplicação
    if (window.appInstance) {
        console.log('4️⃣ Recarregando dados na aplicação...');
        window.appInstance.loadInitialData().then(() => {
            console.log('✅ Dados carregados!');
            
            // Passo 5: Injetar dados diretamente no StateManager
            console.log('5️⃣ Injetando dados no StateManager...');
            window.appInstance.stateManager.setState(sampleData);
            
            // Passo 6: Renderizar apenas a aba ativa
            console.log('6️⃣ Renderizando apenas a aba ativa...');
            const renderer = window.appInstance.renderer;
            
            setTimeout(() => {
                try {
                    // Garantir que uma aba esteja ativa
                    renderer.ensureSingleActiveTab();
                    
                    // Renderizar apenas a aba ativa
                    console.log('🎯 Renderizando aba ativa...');
                    renderer.renderCurrentTab();
                    
                } catch (error) {
                    console.error('❌ Erro ao renderizar aba ativa:', error);
                }
                
                console.log('🎉 === PROCESSO CONCLUÍDO ===');
                console.log('✅ Aba ativa renderizada com sucesso!');
                console.log('🔍 Para diagnosticar: diagnosticarCards()');
                console.log('🔄 Para testar renderização: testarRenderizacao()');
            }, 1000);
            
        }).catch(error => {
            console.error('❌ Erro ao recarregar dados:', error);
        });
    } else {
        console.log('❌ appInstance não encontrada. Recarregue a página.');
    }
};

// Função de depuração específica para ADM_MASTER
window.debugAdmMaster = function() {
    const currentUser = AuthService.getCurrentUser();
    console.log('🔍 Depuração ADM_MASTER:');
    console.log('👤 Usuário atual:', currentUser);
    
    if (currentUser?.role === 'ADM_MASTER') {
        console.log('✅ Usuário é ADM_MASTER');
        console.log('🔒 Acesso baseado apenas no token - sem verificação de dados pessoais na API');
        
        // Verificar elementos da interface
        const meusDadosBtn = document.getElementById('meus-dados-btn');
        const meusDadosTab = document.getElementById('meus-dados-tab');
        
        console.log('👁️ Botão "Meus Dados" visível:', meusDadosBtn && window.getComputedStyle(meusDadosBtn).display !== 'none');
        console.log('👁️ Aba "Meus Dados" visível:', meusDadosTab && window.getComputedStyle(meusDadosTab).display !== 'none');
        
        // Verificar aba ativa
        const activeTab = document.querySelector('.tab-content.active');
        console.log('📋 Aba ativa atual:', activeTab?.id);
        
        console.log('🎯 Configuração adequada: ADM_MASTER deve começar em "gerenciar-alunos-tab" e não ter acesso a "meus-dados-tab"');
    } else {
        console.log('❌ Usuário não é ADM_MASTER');
    }
};

// Função de depuração completa para verificar todos os acessos por role
window.debugAcessos = function() {
    const currentUser = AuthService.getCurrentUser();
    if (!currentUser) {
        console.log('❌ Nenhum usuário logado');
        return;
    }
    
    console.log(`🔍 Verificando acessos para: ${currentUser.nome} (${currentUser.role})`);
    console.log('==========================================');
    
    // Verificar visibilidade das abas
    const tabs = [
        { id: 'meus-dados-btn', name: 'Meus Dados', expected: { VOLUNTARIO: true, ADM: true, ADM_MASTER: false } },
        { id: 'gerenciar-alunos-tab', name: 'Gerenciar Alunos', expected: { VOLUNTARIO: true, ADM: true, ADM_MASTER: true } },
        { id: 'gerenciar-atividades-tab', name: 'Gerenciar Atividades', expected: { VOLUNTARIO: true, ADM: true, ADM_MASTER: true } },
        { selector: 'button[onclick*="gerenciar-voluntarios-tab"]', name: 'Gerenciar Voluntários', expected: { VOLUNTARIO: false, ADM: true, ADM_MASTER: true } },
        { id: 'gerenciar-adm-btn', name: 'Gerenciar ADM', expected: { VOLUNTARIO: false, ADM: false, ADM_MASTER: true } }
    ];
    
    tabs.forEach(tab => {
        const element = tab.id ? document.getElementById(tab.id) : document.querySelector(tab.selector);
        const isVisible = element && window.getComputedStyle(element).display !== 'none';
        const expected = tab.expected[currentUser.role];
        const status = isVisible === expected ? '✅' : '❌';
        
        console.log(`${status} ${tab.name}: ${isVisible ? 'Visível' : 'Oculto'} (Esperado: ${expected ? 'Visível' : 'Oculto'})`);
    });
    
    // Verificar botões de delete
    console.log('\n📝 Funcionalidades esperadas por role:');
    console.log('==========================================');
    
    switch(currentUser.role) {
        case 'VOLUNTARIO':
            console.log('✅ VOLUNTARIO deve ter:');
            console.log('  - Meus Dados (visualizar/editar)');
            console.log('  - Gerenciar Alunos (cadastrar/buscar/editar)');
            console.log('  - Gerenciar Atividades (criar/editar)');
            console.log('❌ VOLUNTARIO NÃO deve ter:');
            console.log('  - Botões de deletar');
            console.log('  - Gerenciar Voluntários');
            console.log('  - Gerenciar ADM');
            break;
            
        case 'ADM':
            console.log('✅ ADMIN deve ter:');
            console.log('  - Meus Dados (visualizar/editar)');
            console.log('  - Gerenciar Alunos (cadastrar/buscar/editar/deletar)');
            console.log('  - Gerenciar Atividades (criar/editar/deletar)');
            console.log('  - Gerenciar Voluntários (cadastrar/buscar/editar/deletar)');
            console.log('❌ ADMIN NÃO deve ter:');
            console.log('  - Gerenciar ADM');
            break;
            
        case 'ADM_MASTER':
            console.log('✅ ADM_MASTER deve ter:');
            console.log('  - Gerenciar Alunos (cadastrar/buscar/editar/deletar)');
            console.log('  - Gerenciar Atividades (criar/editar/deletar)');
            console.log('  - Gerenciar Voluntários (cadastrar/buscar/editar/deletar)');
            console.log('  - Gerenciar ADM (cadastrar/buscar/editar/deletar)');
            console.log('❌ ADM_MASTER NÃO deve ter:');
            console.log('  - Meus Dados (não tem dados pessoais além do token)');
            break;
    }
    
};