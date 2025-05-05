        require("dotenv").config();
        const express = require("express");
        const mongoose = require("mongoose");
        const cors = require("cors");
       // const multer = require("multer");
      //  const path = require("path");
        //const jwt = require("jsonwebtoken");
        //const bcrypt = require("bcrypt");
        const app = express();
        const PORT = process.env.PORT || 5050;

        // Middleware
        app.use(express.json());
        app.use(cors());
        app.use("/uploads", express.static("uploads"));

        // Connexion à MongoDB Atlas
        mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        })
        .then(() => console.log("✅ MongoDB Atlas Connected"))
        .catch(err => console.error("❌ MongoDB Connection Error:", err));

        // Schéma des offres d'emploi
        const offreSchema = new mongoose.Schema({
            titre: String,
            description: String,
            entreprise: { type: String, required: true },
            lieu: String, 
            salaire: Number,
            date_publication: Date,
            id_recruteur: String, 
            candidatures: [{ type: mongoose.Schema.Types.ObjectId, ref: "Candidature" }]
        });
        const Offre = mongoose.model("Offre", offreSchema, "offres");

        // Schéma des candidatures
        const candidatureSchema = new mongoose.Schema({
            id_offre: { type: mongoose.Schema.Types.ObjectId, ref: "Offre", required: true },
            id_candidat: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
            cv: String,
            lettre_motivation: String,
            statut: { type: String, default: "en cours" },
            date_postulation: { type: Date, default: Date.now }
        });
        
        const Candidature = mongoose.model("Candidature", candidatureSchema, "candidatures");
        

        const userSchema = new mongoose.Schema({
            nom: String,
            prenom: String,
            email: { type: String, unique: true, required: true },
            mot_de_passe: { type: String, required: true },
            role: { type: String, default: "candidat" }
        });
        
        const User = mongoose.model("User", userSchema, "users");
        app.get("/", (req, res) => {
            res.send("Welcome to the API! Use /products to get data.");
        });
        app.post("/signup", async (req, res) => {
                    const { nom, prenom, email, mot_de_passe, role } = req.body; // Ajouter le rôle
                    try {
                        const existingUser = await User.findOne({ email });
                        if (existingUser) {
                            return res.status(400).json({ message: "Email déjà utilisé !" });
                        }
                        const hashedPassword = await bcrypt.hash(mot_de_passe, 10);
                        const newUser = new User({ nom, prenom, email, mot_de_passe: hashedPassword, role }); // Inclure le rôle
                        await newUser.save();
                        res.status(201).json({ message: "Utilisateur enregistré avec succès !" });
                    } catch (error) {
                        res.status(500).json({ error: "Erreur lors de l'inscription" });
                    }
                });

                 app.post("/login", async (req, res) => {
                            const { email, mot_de_passe } = req.body;
                            try {
                                const user = await User.findOne({ email });
                                console.log("Utilisateur trouvé :", user); // 🔍 Ajout du log
                        
                                if (!user) {
                                    return res.status(400).json({ message: "Email ou mot de passe incorrect !" });
                                }
                        
                                const isMatch = await bcrypt.compare(mot_de_passe, user.mot_de_passe);
                                console.log("Mot de passe valide :", isMatch); // 🔍 Vérification du mot de passe
                        
                                if (!isMatch) {
                                    return res.status(400).json({ message: "Email ou mot de passe incorrect !" });
                                }
                        
                                const token = jwt.sign({ id: user._id, role: user.role }, "SECRET_KEY", { expiresIn: "24h" });
                                res.status(200).json({ message: "Connexion réussie !", token, user });
                        
                            } catch (error) {
                                console.error("❌ Erreur lors de la connexion :", error);
                                res.status(500).json({ error: "Erreur lors de la connexion" });
                            }
                        });

                        app.get("/users", async (req, res) => {
                            try {
                                // Fetch recruiters (role = 'recruteur') and candidates (role = 'candidat')
                                const recruteurs = await User.find({ role: 'recruteur' });
                                const candidats = await User.find({ role: 'candidat' });
                    
                                // Return both recruiters and candidates in a single response
                                res.status(200).json({ recruteurs, candidats });
                            } catch (err) {
                                console.error("Erreur lors de la récupération des utilisateurs", err);
                                res.status(500).json({ error: "Erreur lors de la récupération des utilisateurs" });
                            }
                        });
                    
                        app.delete("/users/:id", async (req, res) => {
                            try {
                            const { id } = req.params;
                            
                            const user = await User.findById(id);
                            if (!user) {
                                return res.status(404).json({ message: "User not found" });
                            }
                        
                            if (user.role === "recruteur") {
                                // ✅ FIRST: Get offers
                                const offers = await Offre.find({ id_recruteur: id }).select("_id");
                                const offerIds = offers.map(offer => offer._id);
                        
                                // ✅ THEN: Delete candidatures
                                if (offerIds.length > 0) {
                                const deletedCandidatures = await Candidature.deleteMany({ id_offre: { $in: offerIds } });
                                console.log(`Deleted ${deletedCandidatures.deletedCount} candidatures from recruiter's offers`);
                                }
                        
                                // ✅ LAST: Delete the offers
                                const deletedOffers = await Offre.deleteMany({ id_recruteur: id });
                                console.log(`Deleted ${deletedOffers.deletedCount} job offers from recruiter ${id}`);
                            }
                        
                            if (user.role === "candidat") {
                                const deletedCandidatures = await Candidature.deleteMany({ id_candidat: id });
                                console.log(`Deleted ${deletedCandidatures.deletedCount} candidatures from candidate ${id}`);
                            }
                        
                            await User.findByIdAndDelete(id);
                        
                            res.status(200).json({ message: "User deleted successfully" });
                            } catch (error) {
                            console.error("Error deleting user:", error);
                            res.status(500).json({ message: "Error deleting user", error: error.message });
                            }
                        });
                        app.delete("/offres/:id", async (req, res) => {
                            try {
                            const { id } = req.params;
                            
                            // Check if offer exists
                            const offer = await Offre.findById(id);
                            if (!offer) {
                                return res.status(404).json({ message: "Job offer not found" });
                            }
                            
                            // Delete all candidatures for this offer
                            const deletedCandidatures = await Candidature.deleteMany({ id_offre: id });
                            console.log(`Deleted ${deletedCandidatures.deletedCount} candidatures for offer ${id}`);
                            
                            // Delete the offer
                            await Offre.findByIdAndDelete(id);
                            
                            res.status(200).json({ message: "Job offer deleted successfully" });
                            } catch (error) {
                            console.error("Error deleting job offer:", error);
                            res.status(500).json({ message: "Error deleting job offer", error: error.message });
                            }
                        });
                        
                        
                        app.get("/offres", async (req, res) => {
                            try {
                                const { titre, lieu } = req.query;
                                let filter = {};
                                if (titre) filter.titre = { $regex: titre, $options: "i" };
                                if (lieu) filter.lieu = { $regex: lieu, $options: "i" };
                        
                                // Limit the results to 6 for the initial fetch
                                const offres = await Offre.find(filter).limit(6);
                                res.status(200).json(offres || []); // Ensure an empty array is returned
                            } catch (err) {
                                res.status(500).json({ error: "Erreur lors de la récupération des offres" });
                            }
                        });
                        app.post("/offres", async (req, res) => {
                            const { titre, description, entreprise, lieu, salaire, id_recruteur } = req.body;
                        
                            // Validation: Ensure all required fields are present
                            if (!titre || !description || !entreprise || !lieu || !id_recruteur) {
                                return res.status(400).json({ message: "Tous les champs requis doivent être remplis !" });
                            }
                        
                            try {
                                const newOffre = new Offre({
                                    titre,
                                    description,
                                    entreprise,
                                    lieu,
                                    salaire: salaire || 0, // Default to 0 if not provided
                                    date_publication: new Date(),
                                    id_recruteur
                                });
                        
                                await newOffre.save();
                                res.status(201).json({ message: "Offre ajoutée avec succès", offre: newOffre });
                            } catch (error) {
                                console.error("❌ Erreur lors de l'ajout de l'offre:", error);
                                res.status(500).json({ message: "Erreur lors de l'ajout de l'offre", error });
                            }
                        });
        
                        app.get("/filters", async (req, res) => {
                            try {
                                const villes = await Offre.distinct("lieu");
                                const titres = await Offre.distinct("titre");
                                res.json({ villes, titres });
                            } catch (err) {
                                res.status(500).json({ error: "Erreur lors de la récupération des filtres" });
                            }
                        });
                        // Route pour récupérer une offre spécifique avec détails
                        app.get("/offre/:id", async (req, res) => {
                            try {
                                const offre = await Offre.findById(req.params.id).populate("candidatures");
                                if (!offre) return res.status(404).json({ message: "Offre non trouvée" });
                                res.json(offre);
                            } catch (err) {
                                res.status(500).json({ message: "Erreur serveur", error: err });
                            }
                        });
                        

                        const verifyToken = (req, res, next) => {
                                    const token = req.header("Authorization"); // "Bearer ey..."
                                
                                    if (!token) {
                                        return res.status(403).json({ message: "Accès refusé. Aucun token fourni." });
                                    }
                                
                                    try {
                                        // Remove "Bearer " if present
                                        const actualToken = token.replace("Bearer ", "");
                                        
                                        // Verify the token
                                        const decoded = jwt.verify(actualToken, "SECRET_KEY");
                                        req.user = decoded; // Pass user data to next middleware
                                        next();
                                    } catch (err) {
                                        if (err.name === "TokenExpiredError") {
                                            return res.status(401).json({ message: "Erreur de vérification de token: Token expiré." });
                                        } else if (err.name === "JsonWebTokenError") {
                                            return res.status(401).json({ message: "Token invalide." });
                                        } else {
                                            return res.status(500).json({ message: "Erreur lors de la vérification du token." });
                                        }
                                    }
                                };
                                app.get("/me", async (req, res) => {
                                    const authHeader = req.headers.authorization;
                                    if (!authHeader) {
                                        return res.status(401).json({ message: "Token manquant" });
                                    }
                                
                                    const token = authHeader.split(" ")[1];
                                
                                    try {
                                        const decoded = jwt.verify(token, "SECRET_KEY");
                                
                                        const user = await User.findById(decoded.id);
                                        if (!user) {
                                        return res.status(404).json({ message: "Utilisateur non trouvé" });
                                        }
                                
                                        res.json({ user });
                                    } catch (error) {
                                        console.error("Erreur de vérification de token:", error);
                                        res.status(401).json({ message: "Token invalide" });
                                    }
                                    });

                                    app.get("/mes-candidatures", verifyToken, async (req, res) => {
                                        try {
                                            const candidatures = await Candidature.find({ id_candidat: req.user.id })
                                                .populate("id_offre", "titre entreprise lieu") // pour avoir les infos de l'offre
                                                .sort({ date_postulation: -1 });
                                
                                            res.status(200).json(candidatures);
                                        } catch (err) {
                                            res.status(500).json({ message: "Erreur lors de la récupération des candidatures", error: err });
                                        }
                                    });

                                    app.get('/offres/recruteur/:id', async (req, res) => { // Ajout de async ici
                                        const id = req.params.id;
                                        console.log("ID reçu:", id);
                                        
                                        try {
                                            const offres = await Offre.find({ id_recruteur: id }); // Correction ici aussi
                                            res.status(200).json(offres);
                                        } catch (error) {
                                            console.error("Erreur serveur:", error); // Ajout d'un log d'erreur
                                            res.status(500).json({ message: "Erreur serveur", error: error.message });
                                        }
                                    });

                                    app.get("/candidatures", verifyToken, async (req, res) => {
                                        try {
                                            // Récupérer les offres créées par le recruteur connecté
                                            const offres = await Offre.find({ id_recruteur: req.recruteurId }).select("_id");
                                    
                                            if (!offres.length) {
                                                return res.status(200).json([]); // Aucun résultat si le recruteur n'a pas d'offres
                                            }
                                    
                                            // Extraire les IDs des offres
                                            const offreIds = offres.map(offre => offre._id);
                                    
                                            // Trouver les candidatures associées à ces offres
                                            const candidatures = await Candidature.find({ id_offre: { $in: offreIds } })
                                                .populate("id_offre", "titre entreprise")
                                                .exec();
                                    
                                            res.status(200).json(candidatures);
                                        } catch (err) {
                                            res.status(500).json({ message: "Erreur lors de la récupération des candidatures", error: err });
                                        }
                                    });


                                    app.get("/candidatures/:recruteurId", async (req, res) => {
                                        try {
                                            const { recruteurId } = req.params;
                                            console.log("🔍 Recruteur ID reçu :", recruteurId);
                                    
                                            // Récupérer les offres de ce recruteur
                                            const offres = await Offre.find({ id_recruteur: recruteurId }).select("_id");
                                    
                                            if (offres.length === 0) {
                                                return res.status(404).json({ message: "Aucune offre trouvée pour ce recruteur" });
                                            }
                                    
                                            const offreIds = offres.map(offre => offre._id);
                                            console.log("📋 Offres trouvées :", offreIds);
                                    
                                            // Récupérer les candidatures liées à ces offres
                                            const candidatures = await Candidature.find({ id_offre: { $in: offreIds } }).populate("id_offre");
                                            console.log("📥 Candidatures trouvées :", candidatures);
                                    
                                            res.status(200).json(candidatures);
                                        } catch (error) {
                                            console.error("❌ Erreur lors de la récupération des candidatures :", error);
                                            res.status(500).json({ error: "Erreur serveur" });
                                        }
                                    });


                                    app.use((req, res, next) => {
                                        res.setHeader("Content-Security-Policy", "script-src 'self' https://apis.google.com https://accounts.google.com");
                                        next();
                                    });


                                    app.put("/candidatures/:id/statut", async (req, res) => {
                                        const { id } = req.params;
                                        const { statut } = req.body;
                                
                                        try {
                                            const updatedCandidature = await Candidature.findByIdAndUpdate(id, { statut }, { new: true });
                                            if (!updatedCandidature) {
                                                return res.status(404).json({ message: "Candidature non trouvée" });
                                            }
                                            res.json({ message: "Statut mis à jour avec succès", candidature: updatedCandidature });
                                        } catch (error) {
                                            res.status(500).json({ error: "Erreur lors de la mise à jour du statut" });
                                        }
                                    });


                                    app.get("/candidatures/confirmees/:recruteurId", async (req, res) => {
                                        try {
                                            const { recruteurId } = req.params;
                                            console.log("🔍 Recruteur ID reçu :", recruteurId);
                                
                                            // Récupérer les offres de ce recruteur
                                            const offres = await Offre.find({ id_recruteur: recruteurId }).select("_id");
                                
                                            if (!offres.length) {
                                                return res.status(200).json({ message: "Aucune offre trouvée pour ce recruteur" });
                                            }
                                
                                            // Extraire les IDs des offres
                                            const offreIds = offres.map(offre => offre._id);
                                
                                            // Trouver les candidatures confirmées associées à ces offres
                                            const candidaturesConfirmees = await Candidature.find({ 
                                                id_offre: { $in: offreIds }, 
                                                statut: "acceptée" 
                                            })
                                            .populate("id_offre", "titre entreprise")
                                            .exec();
                                
                                            res.status(200).json(candidaturesConfirmees);
                                        } catch (err) {
                                            res.status(500).json({ message: "Erreur lors de la récupération des candidatures confirmées", error: err });
                                        }
                                    });

                                    app.get("/candidatures/statistiques/:recruteurId", async (req, res) => {
                                        try {
                                            const { recruteurId } = req.params;
                                            console.log("🔍 Recruteur ID reçu :", recruteurId);
                                
                                            // Récupérer les offres créées par le recruteur
                                            const offres = await Offre.find({ id_recruteur: recruteurId }).select("_id");
                                
                                            if (!offres.length) {
                                                return res.status(200).json({ 
                                                    message: "Aucune offre trouvée pour ce recruteur", 
                                                    statistiques: { en_cours: 0, refusees: 0, acceptees: 0 } 
                                                });
                                            }
                                
                                            // Extraire les IDs des offres
                                            const offreIds = offres.map(offre => offre._id);
                                
                                            // Compter les candidatures en fonction de leur statut
                                            const statistiques = await Candidature.aggregate([
                                                { $match: { id_offre: { $in: offreIds } } },
                                                { $group: { _id: "$statut", count: { $sum: 1 } } }
                                            ]);
                                
                                            // Transformer les résultats en un objet plus lisible
                                            const stats = {
                                                en_cours: 0,
                                                refusees: 0,
                                                acceptees: 0
                                            };
                                
                                            statistiques.forEach(stat => {
                                                if (stat._id === "en cours") stats.en_cours = stat.count;
                                                if (stat._id === "refusée") stats.refusees = stat.count;
                                                if (stat._id === "acceptée") stats.acceptees = stat.count;
                                            });
                                
                                            res.status(200).json({ recruteurId, statistiques: stats });
                                        } catch (err) {
                                            res.status(500).json({ message: "Erreur lors de la récupération des statistiques des candidatures", error: err });
                                        }
                                    });
                                
                                
        // Démarrer le serveur
        app.listen(PORT, () => {   
            console.log(`🚀 Serveur en cours d'exécution sur http://localhost:${PORT}`);
        });
            
        module.exports = app;
